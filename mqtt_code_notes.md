MQTT 编程过程遇到的问题总结

# 注意 mqtt3.1.1 和 mqtt5.0 CONNACK 中 reason code
> [MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718033)  
> [MQTT Version 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901079)  
    
如果要同时支持 mqtt3.1.1 和 mqtt5.0，在通过 reason code 判断连接是否成功时要根据版本判断，前者只有 0 才是成功，后者小于 0x80 且不为负数都成功。 


# keepalive 计时
> [MQTT Version 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901045)  

对于 broker，如果在 1.5 倍的 keep alive 时间内没有收到 mqtt 消息，则断开连接。  
对于 client，在发送心跳包 PINGRESP 后特定时间没有收到 PINGREQ 回复，则断开连接，这个时间由客户端自己定义。  
对于 client，可以在任意时间发送心跳包，不受设置的 keep alive 时间限制。  
如果上层 keepalive 时间设置为 0s，则 broker 不会检查心跳，即网络断开后 broker 可能连接状态仍显示已连接。
但客户端实现可以不受 keepalive 时间影响，仍可以发送心跳包探测连接状态。

## 示例

```c
// MQTT客户端状态结构体
typedef struct {
    uint16_t keepalive_interval;     // 保活间隔（秒）
    uint32_t last_activity_time;     // 最后活动时间戳（毫秒）
    uint32_t last_ping_time;         // 最后发送PINGREQ的时间戳
    bool is_pending_response;        // 是否有未响应的PING请求
    uint8_t connection_state;        // 连接状态
    // 其他MQTT相关字段...
} MqttClientContext;

// 系统时间函数（需要根据实际平台实现）
uint32_t get_current_timestamp(void);
```

### Keep-Alive 检查实现

```c
// Keep-Alive检查函数
bool check_mqtt_keepalive(MqttClientContext* context)
{
    // 不需要保活机制
    if (context->keepalive_interval == 0) {
        return true;
    }
    
    uint32_t current_time = get_current_timestamp();
    
    // 计算自上次活动以来的时间（毫秒）
    uint32_t time_since_activity = current_time - context->last_activity_time;
    
    // 检查是否需要发送PINGREQ
    if (time_since_activity >= context->keepalive_interval * 1000) {
        if (!context->is_pending_response) {
            // 发送PINGREQ
            if (send_mqtt_ping_request(context)) {
                context->is_pending_response = true;
                context->last_ping_time = current_time;
                // 发送PINGREQ也是一种活动，更新最后活动时间
                context->last_activity_time = current_time;
                printf("Sent PINGREQ at %lu ms\n", current_time);
            }
        } else {
            // 已有未响应的PINGREQ，检查是否超时（1.5倍保活间隔）
            uint32_t time_since_ping = current_time - context->last_ping_time;
            uint32_t timeout_threshold = context->keepalive_interval * 1500;
            
            if (time_since_ping >= timeout_threshold) {
                // PINGRESP未在1.5倍保活间隔内到达，断开连接
                printf("PINGRESP timeout after %lu ms (threshold: %lu ms)\n", 
                       time_since_ping, timeout_threshold);
                context->connection_state = DISCONNECTED;
                return false;
            }
        }
    }
    
    return true;
}
```

### 数据包处理函数

```c
// 当接收到任何数据包时
void handle_incoming_packet(MqttClientContext* context, uint8_t packet_type)
{
    uint32_t current_time = get_current_timestamp();
    
    // 更新最后活动时间
    context->last_activity_time = current_time;
    
    // 如果是PINGRESP，清除等待标志
    if (packet_type == MQTT_PACKET_TYPE_PINGRESP) {
        context->is_pending_response = false;
        printf("Received PINGRESP at %lu ms\n", current_time);
    }
}

// 当发送任何数据包时（除了PINGREQ）
void handle_outgoing_packet(MqttClientContext* context)
{
    // 更新最后活动时间（PINGREQ在保活检查中已更新）
    context->last_activity_time = get_current_timestamp();
}
```

### 主循环示例

```c
// 主循环函数
void mqtt_client_main_loop(void)
{
    MqttClientContext mqtt_context;
    
    // 初始化MQTT客户端
    init_mqtt_client(&mqtt_context);
    mqtt_context.keepalive_interval = 60; // 60秒保活间隔
    
    uint32_t last_keepalive_check = 0;
    uint32_t last_data_report = 0;
    
    while (1) {
        uint32_t current_time = get_current_timestamp();
        
        // 定期检查保活（例如每秒一次）
        if (current_time - last_keepalive_check >= 1000) {
            if (!check_mqtt_keepalive(&mqtt_context)) {
                printf("Connection lost, attempting to reconnect...\n");
                reconnect_mqtt_client(&mqtt_context);
            }
            last_keepalive_check = current_time;
        }
        
        // 处理接收到的MQTT消息
        process_mqtt_messages(&mqtt_context);
        
        // 短暂休眠
        delay_ms(10);
    }
}
```

# 发布主题格式检查
> [MQTT Version 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Topic_Names_and)  
> [MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718106)  

发布的主题不能包含通配符，上层最好做格式检查，及时提醒用户格式错误。

# 订阅主题格式检查
> [MQTT Version 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Topic_Names_and)  
> [MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718106)  

订阅主题可以包含通配符，但有要求，因此上层也需要做格式检查。

但要注意和自身业务匹配，如上层 mqtt 使用如果是下面场景：
客户端收到 broker 发过来的任意主题，都会回复，如果属于定义的 schema 则回复相应内容，否则回复失败的内容。
这种情况注意限制订阅通配符，如订阅 # 通配符匹配任意主题，则本客户端收到 broker 发过来的主题后，回复某个 topic 的内容给 broker，broker 再将这个主题发送给所有订阅该主题的客户端（包括本客户端自己），因此本客户端又收到自己发布过的主题，从而造成消息循环。
除非客户端进行处理，如不对自己发布的主题进行回复。

还要注意，发布和订阅的主题尽量不要相同。
