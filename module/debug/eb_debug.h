#ifndef __EB_DEBUG_H__
#define __EB_DEBUG_H__

#define EB_ERROR(tag, exp, n)           assert(exp)
#define EB_WARNING(tag, exp, n)         do{if(!(exp)){printf(tag "Warning: 0x%02X %s@%d\n", n, __func__, __LINE__);}}while(0)
#define EB_INFO(tag, fmt, ...)            do{printf(tag fmt, ##__VA_ARGS__);}while(0)
#define EB_DUMP(tag, msg, buf, len)       do{printf(tag msg);int i; for(i=0;i<len;i++)printf("%02X ", ((uint8_t*)buf)[i]);printf("\n");}while(0)

#endif /* __EB_DEBUG_H__ */

