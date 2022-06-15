#ifndef __EB_PENDING_H__
#define __EB_PENDING_H__

struct eb_pending;

/*******************************************************************************
 * Create pending module
 * @return   the pointer of pending module
 ******************************************************************************/
struct eb_pending *eb_pending_create(void);

/*******************************************************************************
 * Pending the process, until eb_pending_trigger called
 * @prarm    pending  the pointer of pending module
 ******************************************************************************/
void eb_pending_wait(struct eb_pending *pending);

/*******************************************************************************
 * Pending the process, until eb_pending_trigger called
 * @prarm    pending  the pointer of pending module
 ******************************************************************************/
void eb_pending_trigger(struct eb_pending *pending);

#endif /* __EB_PENDING_H__ */
