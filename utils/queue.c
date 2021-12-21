/* Development : Nikos Boumakis, 4346
 * Email : csd4346 @csd.uoc.gr */

#include "queue.h"
#include <stdlib.h>

struct Queue_node {
    void *elem;
    struct Queue_node *next;
};

struct Queue {
    struct Queue_node *head;
    struct Queue_node *tail;
    int count;
};

/* Creates a new, empty queue. Memory the queue will be allocated dynamically */
Queue_t new_queue() {
    Queue_t queue = malloc(sizeof(queue));
    queue->count = 0;
    queue->head = NULL;
    queue->tail = NULL;

    return queue;
}
/* Completely deletes the queue. After this operation all accesses to the queue will
 * result in undefined behavior. Note that the elements contained in the queue are
 * unaffected. Advised to use this only when the elements are either statically
 * allocated, the queue is empty or the pointers to dynamically allocated elements
 * are held elseware too. */
void delete_queue(Queue_t queue) {
    while (queue->count) {
        dequeue(queue);
    }

    free(queue);
}

/* Append elem to the end of the queue */
void enqueue(Queue_t queue, void *elem) {
    struct Queue_node *node = malloc(sizeof(struct Queue_node));
    node->elem = elem;

    node->next = NULL;
    queue->count++;

    if (queue->head == NULL) {
        queue->head = node;
        queue->tail = node;

        return;
    }

    queue->tail->next = node;
    queue->tail = node;
}

/* Remove and return the element at the start of the queue. The queue is shortened
 * and memory is freed. Returns NULL if the queue was already empty. */
void *dequeue(Queue_t queue) {
    struct Queue_node *tmp = queue->head;
    void *elem;
    if (tmp == NULL) {
        return NULL;
    }

    queue->head = queue->head->next;

    if (queue->head == NULL) {
        queue->tail = NULL;
    }

    elem = tmp->elem;
    free(tmp);
    queue->count--;

    return elem;
}

/* Return the element at the start of the queue. The queue is unaffected, i.e.
 * multiple consecutive calls will always return the same element. If the queue is
 * empty, NULL will be returned. */
void *queue_head(Queue_t queue) {
    if (queue->head == NULL) {
        return NULL;
    }

    return queue->head->elem;
}

/* Return the number of elements in the queue, or zero if the queue is empty */
int queue_count(Queue_t queue) { return queue->count; }

/* Return 1 if there is at least one element in the queue, 0 otherwise */
int queue_isEmpty(Queue_t queue) { return queue->count == 0; }