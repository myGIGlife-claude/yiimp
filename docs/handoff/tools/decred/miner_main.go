// Minimal Decred BLAKE3 stratum test miner, protocol as gominer (stratum/stratum.go):
// subscribe -> [.., extranonce1 (<=4 bytes), extranonce2 size (4..12)]
// notify    -> [job, prevhash, genTx1 (header[36:180]), genTx2, [], version, nbits, ntime, clean]
// work      -> version|prev|genTx1, extranonce1 at 144, extranonce2 (4 bytes) at 148
// submit    -> [user, job, extranonce2, ntime, nonce] (little endian hex as serialized)
// share target = powLimit / diff (mainnet powLimit 2^224-1, like gominer on mainnet)
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"lukechampine.com/blake3"
)

type msg struct {
	ID     interface{}     `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

type job struct {
	id     string
	header [180]byte
	ntime  uint32
}

func main() {
	addr := flag.String("o", "127.0.0.1:3252", "stratum")
	user := flag.String("u", "Ssa44boqASt4eqjhQaEQkawgvT8cMmTCi8Q.w1", "user")
	pass := flag.String("p", "x", "password")
	maxShares := flag.Int("n", 20, "stop after n accepted shares")
	rollTime := flag.Bool("roll", true, "roll ntime like gominer")
	flag.Parse()

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	w := bufio.NewWriter(conn)
	var wmu sync.Mutex
	send := func(id int, method string, params interface{}) {
		b, _ := json.Marshal(map[string]interface{}{"id": id, "method": method, "params": params})
		wmu.Lock()
		w.Write(b)
		w.WriteString("\n")
		w.Flush()
		wmu.Unlock()
	}
	send(1, "mining.subscribe", []string{"decred-gominer/2.1.0"})
	send(2, "mining.authorize", []string{*user, *pass})

	powLimit := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 224), big.NewInt(1))
	var mu sync.Mutex
	var cur *job
	var en1 []byte
	var target *big.Int
	en2size := 0
	accepted, rejected := 0, 0
	gen := 0

	go func() {
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				log.Fatal("read: ", err)
			}
			var m msg
			if err := json.Unmarshal(line, &m); err != nil {
				log.Printf("bad json %s", line)
				continue
			}
			switch m.Method {
			case "mining.set_difficulty":
				var p []float64
				json.Unmarshal(m.Params, &p)
				t := new(big.Float).Quo(new(big.Float).SetInt(powLimit), big.NewFloat(p[0]))
				ti, _ := t.Int(nil)
				mu.Lock()
				target = ti
				mu.Unlock()
				log.Printf("difficulty %v", p[0])
			case "mining.notify":
				var p []interface{}
				json.Unmarshal(m.Params, &p)
				prev, _ := hex.DecodeString(p[1].(string))
				gtx1, _ := hex.DecodeString(p[2].(string))
				ver, _ := hex.DecodeString(p[5].(string))
				nt, _ := hex.DecodeString(p[7].(string))
				j := &job{id: p[0].(string)}
				copy(j.header[0:], ver)
				copy(j.header[4:], prev)
				copy(j.header[36:], gtx1)
				j.ntime = binary.LittleEndian.Uint32(nt)
				mu.Lock()
				copy(j.header[144:], en1)
				cur = j
				gen++
				mu.Unlock()
				log.Printf("job %s height %d prev %x", j.id, binary.LittleEndian.Uint32(j.header[128:]), prev[:8])
			case "":
				id := fmt.Sprint(m.ID)
				if id == "1" {
					var res []interface{}
					json.Unmarshal(m.Result, &res)
					e, _ := hex.DecodeString(res[1].(string))
					mu.Lock()
					en1 = e
					en2size = int(res[2].(float64))
					mu.Unlock()
					log.Printf("subscribed extranonce1 %x extranonce2 size %d", e, en2size)
				} else if id == "2" {
					log.Printf("authorize: %s %s", m.Result, m.Error)
				} else {
					mu.Lock()
					if string(m.Result) == "true" {
						accepted++
					} else {
						rejected++
					}
					a := accepted
					mu.Unlock()
					log.Printf("share %s: %s %s (accepted %d, rejected %d)", id, m.Result, m.Error, a, rejected)
					if a >= *maxShares {
						log.Printf("done")
						conn.Close()
						return
					}
				}
			default:
				log.Printf("%s %s", m.Method, m.Params)
			}
		}
	}()

	sid := 10
	var en2 uint32 = 0x01000000
	for {
		mu.Lock()
		j, t, g := cur, target, gen
		mu.Unlock()
		if j == nil || t == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		hdr := j.header
		en2++
		binary.LittleEndian.PutUint32(hdr[148:], en2)
		ts := j.ntime
		if *rollTime {
			ts = uint32(time.Now().Unix())
			if ts < j.ntime {
				ts = j.ntime
			}
		}
		binary.LittleEndian.PutUint32(hdr[136:], ts)
		for nonce := uint32(0); nonce < 1<<22; nonce++ {
			binary.LittleEndian.PutUint32(hdr[140:], nonce)
			h := blake3.Sum256(hdr[:])
			// hash as a little endian uint256
			var be [32]byte
			for i := 0; i < 32; i++ {
				be[i] = h[31-i]
			}
			if new(big.Int).SetBytes(be[:]).Cmp(t) <= 0 {
				sid++
				log.Printf("found share job %s nonce %08x pow %x", j.id, nonce, be)
				send(sid, "mining.submit", []string{*user, j.id,
					hex.EncodeToString(hdr[148:152]), hex.EncodeToString(hdr[136:140]), hex.EncodeToString(hdr[140:144])})
				break
			}
			if nonce&0xffff == 0 {
				mu.Lock()
				stale := gen != g
				mu.Unlock()
				if stale {
					break
				}
			}
		}
	}
}
