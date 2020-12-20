#ifndef MMINLINE_H_
#define MMINLINE_H_
// This file defines inline functions to manipulate blocks and the free list
// NOTE: to be included only in mm.c

static block_t *flist_first;  // head of circular, doubly linked free list

// returns a pointer to the block's end tag (You probably won't need to use this
// directly)
static inline size_t *block_end_tag(block_t *b) {
    assert(b->size >= (WORD_SIZE * 2));
    return &b->payload[(b->size / WORD_SIZE) - 2];
}

// returns 1 if block is allocated, 0 otherwise
// In other words, returns 1 if the right-most bit in b->size is set, 0
// otherwise
static inline int block_allocated(block_t *b) { return b->size & 1; }

// same as the above, but checks the end tag of the block
// NOTE: since b->size is divided by WORD_SIZE, the 3 right-most bits are
// truncated (including the 'is-allocated' bit)
static inline int block_end_allocated(block_t *b) {
    return *block_end_tag(b) & 1;
}

// returns the size of the entire block
// NOTE: -2 is 111...1110 in binary, so the '& -2' removes the 'is-allocated'
// bit from the size
static inline size_t block_size(block_t *b) { return b->size & -2; }

// same as the above, but uses the end tag of the block
static inline size_t block_end_size(block_t *b) {
    return *block_end_tag(b) & -2;
}

// Sets the entire size of the block at both the beginning and the end tags.
// Preserves the alloc bit (if b is marked allocated or free, it will remain
// so).
// NOTE: size must be a multiple of ALIGNMENT, which means that in binary, its
// right-most 3 bits must be 0.
// Thus, we can check if size is a multiple of ALIGNMENT by &-ing it with
// ALIGNMENT - 1, which is 00..00111 in binary if ALIGNMENT is 8.
static inline void block_set_size(block_t *b, size_t size) {
    assert((size & (ALIGNMENT - 1)) == 0);
    // alloc bit is always 0 to start with if the above assert passes
    size |= block_allocated(b);
    b->size = size;
    *block_end_tag(b) = size;
}

// Sets the allocated flags of the block, at both the beginning and the end
// tags.
// NOTE: -2 is 111...1110 in binary
static inline void block_set_allocated(block_t *b, int allocated) {
    assert((allocated == 0) || (allocated == 1));
    if (allocated) {
        b->size |= 1;
        *block_end_tag(b) |= 1;
    } else {
        b->size &= -2;
        *block_end_tag(b) &= -2;
    }
}

// Sets the entire size of the block and sets the allocated flags of the block,
// at both the beginning and the end
static inline void block_set_size_and_allocated(block_t *b, size_t size,
                                                int allocated) {
    block_set_size(b, size);
    block_set_allocated(b, allocated);
}

// returns 1 if the previous block is allocated, 0 otherwise
static inline int block_prev_allocated(block_t *b) {
    size_t *tag = ((size_t *)b) - 1;
    return *tag & 1;
}

// returns the size of the previous block
// NOTE: -2 is 111...1110 in binary
static inline size_t block_prev_size(block_t *b) {
    size_t *tag = ((size_t *)b) - 1;
    return *tag & -2;
}

// returns a pointer to the previous block
static inline block_t *block_prev(block_t *b) {
    return (block_t *)((char *)b - block_prev_size(b));
}

// returns a pointer to the next block
static inline block_t *block_next(block_t *b) {
    return (block_t *)((char *)b + block_size(b));
}

// returns 1 if the next block is allocated; 0 if not
static inline size_t block_next_allocated(block_t *b) {
    return block_allocated(block_next(b));
}

// returns the size of the next block
static inline size_t block_next_size(block_t *b) {
    return block_size(block_next(b));
}

// given a pointer to the payload, returns a pointer to the block
static inline block_t *payload_to_block(void *payload) {
    return (block_t *)((size_t *)payload - 1);
}

// returns a pointer to the next free block
// NOTE: if 'b' is free, b->payload[0] contains a pointer to the next free block
static inline block_t *block_next_free(block_t *b) {
    assert(!block_allocated(b));
    return (block_t *)b->payload[0];
}

// sets the pointer to the next free block
static inline void block_set_next_free(block_t *b, block_t *next) {
    assert(!block_allocated(b) && !block_allocated(next));
    b->payload[0] = (size_t)next;
}

// returns a pointer to the previous free block
// NOTE: if 'b' is free, b->payload[1] contains a pointer to the previous free
// block
static inline block_t *block_prev_free(block_t *b) {
    assert(!block_allocated(b));
    return (block_t *)b->payload[1];
}

// sets the pointer to the previous free block
static inline void block_set_prev_free(block_t *b, block_t *prev) {
    assert(!block_allocated(b) && !block_allocated(prev));
    b->payload[1] = (size_t)prev;
}

// pull a block from the (circularly doubly linked) free list
static inline void pull_free_block(block_t *fb) {
    assert(!block_allocated(fb));
    if (flist_first == fb) {
        if ((flist_first = block_next_free(fb)) == fb) {
            flist_first = NULL;
            return;
        }
    }
    block_set_next_free(block_prev_free(fb), block_next_free(fb));
    block_set_prev_free(block_next_free(fb), block_prev_free(fb));
}

// insert block into the (circularly doubly linked) free list
static inline void insert_free_block(block_t *fb) {
    assert(!block_allocated(fb));
    if (flist_first != NULL) {
        block_t *last = block_prev_free(flist_first);
        // put 'fb' in between 'flist_first' and 'last'
        block_set_next_free(fb, flist_first);
        block_set_prev_free(fb, last);
        // update 'last' and 'flist_first' so they point to 'fb'
        block_set_next_free(last, fb);
        block_set_prev_free(flist_first, fb);
    } else {
        // The free list is empty, so when we insert fb, it will be the
        // only element in the list.
        // Thus it needs to point to itself from both next and prev
        // (since the list is circular)
        block_set_next_free(fb, fb);
        block_set_prev_free(fb, fb);
    }
    flist_first = fb;
}

#endif  // MMINLINE_H_
