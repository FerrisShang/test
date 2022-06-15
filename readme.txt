hci    |  master / slave
       |  | conn / scan / adv / ext scan / ext adv / per adv / sync trans / cte / cis / bis /
l2cap  |  credit base 
gatt   |  client / server
       |  | opcode support
smp    |  master / slave
       |  | sc opcode support

memory release..
l2cap reserved buffer for sending acl data
l2cap 发送buffer由用户提供，并且上层提供free接口,发送内存可以用ringbuffer方式，因为数据是顺序释放
l2cap 配置采用套餐形式，调用接口直接用给好的参数即可
