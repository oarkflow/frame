/*
 * Copyright 2022 CloudWeGo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"

	"github.com/oarkflow/log"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/middlewares/server/etag"
	logMiddleware "github.com/oarkflow/frame/middlewares/server/log"
	"github.com/oarkflow/frame/server"
)

func main() {
	h := server.New(server.WithHostPorts("127.0.0.1:8080"), server.WithStreamBody(true))
	h.Use(etag.New())
	h.Use(logMiddleware.New(logMiddleware.Config{
		Logger: &log.DefaultLogger,
	}))
	h.GET("/streamWrite", handler1)

	// Demo: synchronized reading and writing
	h.GET("/syncWrite", handler2)

	h.Spin()
}

func handler1(ctx context.Context, c *frame.Context) {
	bs := []byte("hello, hertz!")
	wb := bytes.NewBuffer(bs)
	c.SetBodyStream(wb, len(bs))
}

func handler2(ctx context.Context, c *frame.Context) {
	data := readFileAsMap()
	c.StreamJSON(data, 100)
}

func readFileAsMap() []map[string]any {
	var d []map[string]any
	data, err := os.Open("./icd10_codes.json")
	if err != nil {
		panic(err)
	}
	decoder := json.NewDecoder(data)
	err = decoder.Decode(&d)
	if err != nil {
		panic(err)
	}
	return d
}
