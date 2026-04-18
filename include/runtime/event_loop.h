#ifndef EVENT_LOOP_H
#define EVENT_LOOP_H

#pragma once

typedef struct event_loop
{
    int backend_fd;
} event_loop_t;

typedef struct event_loop_event
{
    int fd;
    int readable;
    int writable;
    int error;
} event_loop_event_t;

/* lifecycle */
void event_loop_reset(event_loop_t *loop);
int event_loop_init(event_loop_t *loop);
void event_loop_destroy(event_loop_t *loop);

/* operations */
int event_loop_add(event_loop_t *loop, int fd);
int event_loop_remove(event_loop_t *loop, int fd);
int event_loop_wait(event_loop_t *loop, event_loop_event_t *out, int max_events);

#endif
