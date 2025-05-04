package main

import "encoding/json"

func buildLarkPayload(data []byte) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"msg_type": "text",
		"content":  map[string]string{"text": string(data)},
	})
}

func buildDingTalkPayload(data []byte) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"msgtype": "text",
		"text":    map[string]string{"content": string(data)},
	})
}

func buildWeComPayload(data []byte) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"msgtype": "text",
		"text":    map[string]string{"content": string(data)},
	})
}
