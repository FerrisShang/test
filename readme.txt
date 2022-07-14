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


=== debug ===
assert_info(exp, fmt, ...)
assert_warning(exp, fmt, ...)
assert_error(exp, fmt, ...)
log_debug(fmt, ...)
log_dump(data, len)
log_warning(fmt, ...)
log_error(fmt, ...)

=== memory ===
只支持 init, malloc, free这几个接口
支持优先级critical,high,mid,low这几种, critical malloc失败直接挂死，高优先级可以抢占低优先级内存

=== API ===
接口用xxx.h文件，内部接口（适配接口）用xxx_int.h文件，内部接口包含外部接口
host接口间采用弱符号方式相互调用，方便适配用户接口
内外接口完全分开，.h不允许混合使用(仅允许接口函数同时访问内外接口)

=== 命名规则 ===
用户接口函数 ebh_xxx
无用户接口变量 -
内部共享函数    ebh_int_mod_xxx
内部static函数  ebh_static_mod_xxx
内部共享变量    ebh_int_mod_xxx
内部共享c变量   ebh_int_const_mod_xxx
内部static变量  ebh_static_mod_xxx
内部cstatic变量 ebh_cstatic_mod_xxx




