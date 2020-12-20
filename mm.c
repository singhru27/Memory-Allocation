#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "./memlib.h"
#include "./mm.h"
#include "./mminline.h"

// Amount of bytes to expand heap by if there is not enough memory
#define HEAP_EXPANSION 512

// rounds up to the nearest multiple of WORD_SIZE
static inline size_t align(size_t size) {
    return (((size) + (WORD_SIZE - 1)) & ~(WORD_SIZE - 1));
}

int mm_check_heap(void);
block_t *extend_heap(size_t size);
block_t *prologue;
block_t *epilogue;

/* Increases the heap size and returns a pointer to the newly created
 * free block.
 * Arguments: size: The desired size to be incremented by
 * Returns: A pointer to the beginning of the newly created free block
 */

block_t *extend_heap(size_t size) {
    size_t expansion_size = size;

    // Setting the expansion size to be a multiple of 8
    expansion_size = align(expansion_size);

    // Checking that the expansion size is at least min_block_size. If it is
    // not, it is set to be the minimum size
    if (expansion_size < MINBLOCKSIZE) {
        expansion_size = MINBLOCKSIZE;
    }

    // Setting "free_block" to point to the current epilogue block
    block_t *free_block = epilogue;

    // Expanding the heap by the expansion_size
    mem_sbrk(expansion_size);

    // Setting the free block to have expansion_size and be free
    block_set_size_and_allocated(free_block, expansion_size, 0);

    // Setting the epilogue block to be the block immediately following
    // the newly created free block
    epilogue = block_next(free_block);
    block_set_size_and_allocated(epilogue, TAGS_SIZE, 1);

    // Checking if the block prior to the newly created block is allocated.
    // If it is, the new block is added to the free list and a pointer is
    // returned If it is not, the previous block is coalesced with the newly
    // created block and a pointer to this block is returned
    if (block_prev_allocated(free_block)) {
        // Adding the free block to the free block list
        insert_free_block(free_block);
        return free_block;
    }

    // Reaching this code indicates that the previous block was free. This means
    // that the previous block must be coalesced with the newly created segment,
    // and a pointer to this larger block of memory is returned
    block_t *previous_block = block_prev(free_block);
    block_set_size(previous_block, expansion_size + block_size(previous_block));
    return previous_block;
}

/*
 *                             _       _ _
 *     _ __ ___  _ __ ___     (_)_ __ (_) |_
 *    | '_ ` _ \| '_ ` _ \    | | '_ \| | __|
 *    | | | | | | | | | | |   | | | | | | |_
 *    |_| |_| |_|_| |_| |_|___|_|_| |_|_|\__|
 *                       |_____|
 *
 * initializes the dynamic storage allocator (allocate initial heap space)
 * arguments: none
 * returns: 0, if successful
 *         -1, if an error occurs
 */
int mm_init(void) {
    // Setting the flist_first to be null
    flist_first = NULL;

    // Initializing the heap, and setting the prologue and epilogue blocks.
    // If the mem_sbrk returned an error, -1 is returned by the function.
    // The prologue and epilogue blocks are set to be "allocated".

    prologue = mem_sbrk(32);
    if (prologue == (void *)-1) {
        return -1;
    }

    block_set_size_and_allocated(prologue, TAGS_SIZE, 1);
    epilogue = block_next(prologue);
    block_set_size_and_allocated(epilogue, TAGS_SIZE, 1);

    return 0;
}

/*     _ __ ___  _ __ ___      _ __ ___   __ _| | | ___   ___
 *    | '_ ` _ \| '_ ` _ \    | '_ ` _ \ / _` | | |/ _ \ / __|
 *    | | | | | | | | | | |   | | | | | | (_| | | | (_) | (__
 *    |_| |_| |_|_| |_| |_|___|_| |_| |_|\__,_|_|_|\___/ \___|
 *                       |_____|
 *
 * allocates a block of memory and returns a pointer to that block's payload
 * arguments: size: the desired payload size for the block
 * returns: a pointer to the newly-allocated block's payload (whose size
 *          is a multiple of ALIGNMENT), or NULL if an error occurred
 */
void *mm_malloc(size_t size) {
    // If the size is 0, NULL is returned
    if (size == 0) {
        return NULL;
    }

    // Rounds up the size to be a multiple of rounded size
    size_t new_block_size = align(size);

    // Adds 16 bytes representing the header and footer to the
    // size of the block
    new_block_size = new_block_size + TAGS_SIZE;

    // Ensuring that the new_block_size is greater than the minimum block
    // size. If it is not, the new_block_size is rounded up to the minimum
    // block size
    if (new_block_size < MINBLOCKSIZE) {
        new_block_size = MINBLOCKSIZE;
    }

    // If the flist is null, extend heap is called to create more space
    // in the heap. The new block is then allocated with the passed in size, and
    // the free block is removed from the free list. A pointer to the payload is
    // then returned

    if (flist_first == NULL) {
        block_t *new_block = extend_heap(new_block_size);
        pull_free_block(new_block);
        block_set_allocated(new_block, 1);
        return new_block->payload;
    }

    // If the flist is not null, all the free blocks in the free list are
    // iterated through. The first block of appropriate size is selected to be
    // allocated into. If the entire list is iterated through without a large
    // enough block being found, new space is created on the heap and this new
    // block is allocated

    block_t *free_block = flist_first;

    // Checking if the first free_block is large enough to be allocated to. If
    // so, this block is allocated
    if (block_size(free_block) >= new_block_size) {
        // First, it is checked whether the size of the free blocks is more than
        // MINBLOCKSIZE greater than the size of the block we are trying to
        // allocate. If it is, the free block is split so that only the needed
        // memory is used from the free block, and the remaining memory is still
        // free
        if (new_block_size + MINBLOCKSIZE <= block_size(free_block)) {
            size_t total_size = block_size(free_block);
            pull_free_block(free_block);
            block_set_size_and_allocated(free_block, new_block_size, 1);

            // Pointer to the portion of the block that remains unused
            block_t *partitioned_free_block = block_next(free_block);
            block_set_size_and_allocated(partitioned_free_block,
                                         total_size - new_block_size, 0);
            insert_free_block(partitioned_free_block);
            return free_block->payload;
        }

        pull_free_block(free_block);
        block_set_allocated(free_block, 1);
        return free_block->payload;
    }

    // If the first free block was not large enough to be allocated to, the
    // entire free blocks list is cycled through to determine if there is a
    // large enough free block.
    free_block = block_next_free(free_block);
    while (free_block != flist_first) {
        // Checking if the currently selected free block is large enough. If it
        // is, it is allocated.
        if (block_size(free_block) >= new_block_size) {
            // First, it is checked whether the size of the free blocks is more
            // than MINBLOCKSIZE greater than the size of the block we are
            // trying to allocate. If it is, the free block is split so that
            // only the needed memory is used from the free block, and the
            // remaining memory is still free
            if (new_block_size + MINBLOCKSIZE <= block_size(free_block)) {
                size_t total_size = block_size(free_block);
                pull_free_block(free_block);
                block_set_size_and_allocated(free_block, new_block_size, 1);

                // Pointer to the portion of the block that remains unused
                block_t *partitioned_free_block = block_next(free_block);
                block_set_size_and_allocated(partitioned_free_block,
                                             total_size - new_block_size, 0);
                insert_free_block(partitioned_free_block);
                return free_block->payload;
            }

            pull_free_block(free_block);
            block_set_allocated(free_block, 1);
            return free_block->payload;
        }

        // If the currently selected free block was not large enough, the
        // free_list is cycled through to the next element
        free_block = block_next_free(free_block);
    }

    // If this code is reached, this means that there was no free block large
    // enough to be allocated. The code thus calls extend_heap to create more
    // space on the heap, and allocates to this newly created space. First, we
    // check if the last block in the heap is free. If it is, we allocate just
    // enough memory so that coalescing this last block with the newly created
    // space will provide enough space to properly malloc. If this last block is
    // not free, we are forced to simply extend the heap by however many bytes
    // we need to allocate
    if (block_prev_allocated(epilogue) == 0) {
        block_t *new_block =
            extend_heap(new_block_size - block_size(block_prev(epilogue)));
        pull_free_block(new_block);
        block_set_allocated(new_block, 1);
        return new_block->payload;
    }

    block_t *new_block = extend_heap(new_block_size);
    pull_free_block(new_block);
    block_set_allocated(new_block, 1);
    return new_block->payload;
}

/*                              __
 *     _ __ ___  _ __ ___      / _|_ __ ___  ___
 *    | '_ ` _ \| '_ ` _ \    | |_| '__/ _ \/ _ \
 *    | | | | | | | | | | |   |  _| | |  __/  __/
 *    |_| |_| |_|_| |_| |_|___|_| |_|  \___|\___|
 *                       |_____|
 *
 * frees a block of memory, enabling it to be reused later
 * arguments: ptr: pointer to the block's payload
 * returns: nothing
 */
void mm_free(void *ptr) {
    // If NULL was passed into the function, nothing happens and the function
    // simply returns

    if (ptr == NULL) {
        return;
    }

    // If a valid pointer was passed into the function, the block is set to be
    // free
    block_t *new_free_block = payload_to_block(ptr);
    block_set_allocated(new_free_block, 0);

    // The following function checks if the block after the passed in block
    // is free. If it is, it is coalesced with the given block

    if (block_next_allocated(new_free_block) == 0) {
        block_t *next_free_block = block_next(new_free_block);

        // Removing the next free block from the free block list
        pull_free_block(next_free_block);

        // Adding the size of the next free block to the size of the newly freed
        // block
        block_set_size(new_free_block, block_size(new_free_block) +
                                           block_next_size(new_free_block));
    }

    // Checking if the block before the passed in block is free. If it is, it is
    // coalesced with the given block
    if (block_prev_allocated(new_free_block) == 0) {
        block_t *previous_free_block = block_prev(new_free_block);

        // Adding the size of the new free block to the size of the previous
        // free block
        block_set_size(previous_free_block, block_size(previous_free_block) +
                                                block_size(new_free_block));

        // Since the previous block is already in the free block list, we can
        // return from the function
        return;
    }

    // Inserting the new free block into the free block list
    insert_free_block(new_free_block);
}

/*
 *                                            _ _
 *     _ __ ___  _ __ ___      _ __ ___  __ _| | | ___   ___
 *    | '_ ` _ \| '_ ` _ \    | '__/ _ \/ _` | | |/ _ \ / __|
 *    | | | | | | | | | | |   | | |  __/ (_| | | | (_) | (__
 *    |_| |_| |_|_| |_| |_|___|_|  \___|\__,_|_|_|\___/ \___|
 *                       |_____|
 *
 * reallocates a memory block to update it with a new given size
 * arguments: ptr: a pointer to the memory block's payload
 *            size: the desired new payload size
 * returns: a pointer to the new memory block's payload
 */
void *mm_realloc(void *ptr, size_t size) {
    // Rounds up the size to be a multiple of rounded size
    size_t new_block_size = align(size);

    // If the passed in pointer is NULL, we simply call malloc (SIZE) and
    // return a pointer to the given payload
    if (ptr == NULL) {
        return mm_malloc(new_block_size);
    }

    // Adds 16 bytes representing the header and footer to the
    // size of the block. This represents the total size that the
    // new block needs to be
    new_block_size = new_block_size + TAGS_SIZE;

    // Ensuring that the new_block_size is greater than the minimum block
    // size. If it is not, the new_block_size is rounded up to the minimummallo
    // block size
    if (new_block_size < MINBLOCKSIZE) {
        new_block_size = MINBLOCKSIZE;
    }

    // Setting a pointer to the block which the payload belongs to
    block_t *original_block = payload_to_block(ptr);

    // If the size is equal to zero, the block pointed to by ptr is freed
    if (size == 0) {
        mm_free(ptr);
        return NULL;
    }

    size_t original_size = block_size(original_block);

    // If the new size is smaller than the current size of the allocated block,
    // we can just shrink the current allocated block. The current allocated
    // block is only shrunk if a new free block which is larger than the
    // MINBLOCKSIZE can be created from the newly freed memory. If such a free
    // block cannot be created, the original block is simply returned.

    if (new_block_size + MINBLOCKSIZE <= original_size) {
        // Setting the current block to be the new smaller size, and setting
        // this block to be allocated
        block_set_size_and_allocated(original_block, new_block_size, 1);

        // Setting the size and allocated bit of the next block, and then
        // calling free on that block to free and coalesce
        block_t *next_free_block = block_next(original_block);
        block_set_size(next_free_block, original_size - new_block_size);
        mm_free(next_free_block->payload);
        return original_block->payload;
    }

    // Simply returning the original block if the newly requested size is
    // smaller or equal to the original size, but not so small that splitting
    // would create another viable free block
    if (new_block_size <= original_size) {
        return original_block->payload;
    }

    // If this code is reached, this means that the new_block_size is larger
    // than the size of the original block. First, we check if the block
    // immediately following the block to be realloc'd is free. If it is, we
    // then check if it is large enough to simply extend into this new space.

    if (block_next_allocated(original_block) == 0) {
        block_t *next_free_block = block_next(original_block);

        // This handles the case for which the next free block is split.
        if (original_size + block_size(next_free_block) >=
            new_block_size + MINBLOCKSIZE) {
            size_t next_original_size = block_size(next_free_block);
            pull_free_block(next_free_block);
            block_set_size_and_allocated(original_block, new_block_size, 1);

            // Setting the next free block to be the block immediately following
            // the newly expanded original block
            next_free_block = block_next(original_block);

            // Setting this new block to be the new shortened size, and setting
            // it to be set as free
            block_set_size_and_allocated(
                next_free_block,
                next_original_size + original_size - new_block_size, 1);
            mm_free(next_free_block->payload);
            return original_block->payload;
        }

        // This handles the case for which expanding into the next free block
        // will yield enough space to fulfill the realloc space, but the next
        // free block is not so large that splitting would be efficient

        if (original_size + block_size(next_free_block) >= new_block_size) {
            pull_free_block(next_free_block);
            block_set_size_and_allocated(
                original_block,
                block_size(original_block) + block_size(next_free_block), 1);
            return original_block->payload;
        }
    }

    // Reaching this code indicates that the newly requested size is too large
    // to be fulfilled by combining the current block with the next block (if it
    // is free). Thus, we first iterate through the entire list of free blocks
    // to determine if there is a free block that is large enough. If it is
    // found, we copy the memory over into this new block, and free the current
    // block of memory

    if (flist_first != NULL) {
        block_t *free_block = flist_first;
        size_t free_block_size = block_size(free_block);

        // This checks if the first free block is large enough to be realloced
        // into, and also large enough to be split into a new usable block
        if (free_block_size >= new_block_size + MINBLOCKSIZE) {
            // Setting the new block to be the new_block_size and removing it
            // from the free list.
            pull_free_block(free_block);
            block_set_size_and_allocated(free_block, new_block_size, 1);

            // Copying over the data from just the payload in the original block
            // into the new block
            memmove(free_block->payload, original_block->payload,
                    original_size - TAGS_SIZE);

            // Setting the freshly split block to be the appropriate size
            block_t *split_free_block = block_next(free_block);
            block_set_size_and_allocated(split_free_block,
                                         free_block_size - new_block_size, 1);

            // Freeing both the original block from which data was copied, and
            // the newly split block

            mm_free(split_free_block->payload);
            mm_free(original_block->payload);

            // Returning the payload of the newly allocated block
            return free_block->payload;
        }

        // This checks if the first free block in the list is large enough to be
        // realloced into, but not large enough to be split
        if (free_block_size >= new_block_size) {
            // Setting the new block to be allocated and removing it from the
            // free list
            pull_free_block(free_block);
            block_set_allocated(free_block, 1);

            // Copying over the data from just the payload in the original block
            // into the new block
            memmove(free_block->payload, original_block->payload,
                    original_size - TAGS_SIZE);

            // Setting the original block to be free
            mm_free(original_block->payload);

            // Returning the payload of the newly allocated block
            return free_block->payload;
        }

        // If the first free block was not large enough to reallocate the needed
        // size into, the entire free list is iterated through to check each
        // available free block to determine if there is enough space for
        // reallocation

        free_block = block_next_free(free_block);

        while (free_block != flist_first) {
            // Setting the free_block_size to be the size of the given free
            // block
            free_block_size = block_size(free_block);

            // This checks if the free block is large enough to be realloced
            // into, and also large enough to be split into a new usable block
            if (free_block_size >= new_block_size + MINBLOCKSIZE) {
                // Setting the new block to be the new_block_size and removing
                // it from the free list.
                pull_free_block(free_block);
                block_set_size_and_allocated(free_block, new_block_size, 1);

                // Copying over the data from just the payload in the original
                // block into the new block
                memmove(free_block->payload, original_block->payload,
                        original_size - TAGS_SIZE);

                // Setting the freshly split block to be the appropriate size
                block_t *split_free_block = block_next(free_block);
                block_set_size_and_allocated(
                    split_free_block, free_block_size - new_block_size, 1);

                // Freeing both the original block from which data was copied,
                // and the newly split block

                mm_free(split_free_block->payload);
                mm_free(original_block->payload);

                // Returning the payload of the newly allocated block
                return free_block->payload;
            }

            // This checks if the first free block in the list is large enough
            // to be realloced into, but not large enough to be split
            if (free_block_size >= new_block_size) {
                // Setting the new block to be allocated and removing it from
                // the free list
                pull_free_block(free_block);
                block_set_allocated(free_block, 1);

                // Copying over the data from just the payload in the original
                // block into the new block
                memmove(free_block->payload, original_block->payload,
                        original_size - TAGS_SIZE);

                // Setting the original block to be free
                mm_free(original_block->payload);

                // Returning the payload of the newly allocated block
                return free_block->payload;
            }

            // If the current free block was not large enough to be realloced
            // into, we iterate through to the next free block in the list and
            // try again
            free_block = block_next_free(free_block);
        }
    }

    // Reaching this code indicates that there was no independent free block
    // that was large enough on its own to be realloced into. This next sequence
    // checks if the block before the currently allocated block is free, and if
    // combining this block with the current block will provide enough space to
    // realloc the block.

    if (block_prev_allocated(original_block) == 0) {
        block_t *previous_free_block = block_prev(original_block);
        size_t previous_original_size = block_size(previous_free_block);

        // If the combined size of the two blocks is big enough to hold the
        // data, with enough space left over to split into a new free block, the
        // data is copied over and a new free block is split out

        if (previous_original_size + original_size >=
            new_block_size + MINBLOCKSIZE) {
            // Removing the previous free block from the free block list
            pull_free_block(previous_free_block);

            // Copying over the data from just the payload in the original block
            // into the new block
            memmove(previous_free_block->payload, original_block->payload,
                    original_size - TAGS_SIZE);

            // Setting the size and allocated tag of the newly alloccated block
            // to be just the new_block_size
            block_set_size_and_allocated(previous_free_block, new_block_size,
                                         1);

            // Iterating through to the next split block, and setting the
            // size/allocated bits of this block, and adding it to the free
            // block list
            block_t *split_free_block = block_next(previous_free_block);
            block_set_size_and_allocated(
                split_free_block,
                previous_original_size + original_size - new_block_size, 1);

            // Freeing the newly split block (which also handles coalescing
            mm_free(split_free_block->payload);

            return previous_free_block->payload;
        }

        // If the combined size of the two blocks is big enough to hold the
        // data, but not big enough to create a viable split new free block,
        // then the two blocks are coalesced and returned
        if (previous_original_size + original_size >= new_block_size) {
            // Removing the previous free block from the free block list
            pull_free_block(previous_free_block);

            // Copying over the data from just the payload in the original block
            // into the new block
            memmove(previous_free_block->payload, original_block->payload,
                    original_size - TAGS_SIZE);

            // Setting the size and allocated tag of the new free block which is
            // now being allocated
            block_set_size_and_allocated(
                previous_free_block, previous_original_size + original_size, 1);

            // Returning the payload of the newly allocated and coalesced block
            return previous_free_block->payload;
        }
    }

    // If there is no way to use already existing space in the heap to realloc
    // the block, then new space is requested using the sbrk system call. This
    // new space is then used to move all the data in the original block over
    // into the new space

    // First, it is checked if the block being realloced is the last block in
    // the heap. If it is, then we only need to request new_block_size -
    // original_size amount of memory, since the resultant block can be
    // coalesced with the block being realloced

    if (block_next(original_block) == epilogue) {
        block_t *new_block = extend_heap(new_block_size - original_size);

        // Removing the new free block from the free block list
        pull_free_block(new_block);

        // This handles the case for which the heap was asked to be extended by
        // less than 32 bytes
        if (new_block_size - original_size < MINBLOCKSIZE) {
            block_set_size_and_allocated(original_block,
                                         original_size + MINBLOCKSIZE, 1);
            return original_block->payload;
        }

        // Coalescing the current original block with the newly created block
        block_set_size_and_allocated(original_block, new_block_size, 1);

        // Returning the payload
        return original_block->payload;
    }

    // Next, we check if the last block in the heap is a free block. Then, we
    // only need to request enough memory such that the size of the final free
    // block + the size of the newly allocated memory is enough to fulfill the
    // realloc request

    if (block_prev_allocated(epilogue) == 0) {
        block_t *final_free_block = block_prev(epilogue);
        size_t final_free_size = block_size(final_free_block);

        // Removing the final free block from the free list
        pull_free_block(final_free_block);

        // Creating a new memory region that is large enough to hold the new
        // block
        block_t *new_block = extend_heap(new_block_size - final_free_size);

        // Copying over the data from the old block into the new block, and
        // setting the new block to be allocated
        memmove(new_block->payload, original_block->payload,
                original_size - TAGS_SIZE);

        // Setting the new free block to be allocated
        block_set_allocated(new_block, 1);

        // Freeing the old block
        mm_free(original_block->payload);

        // Returning the payload from the original block
        return new_block->payload;
    }

    block_t *new_block = extend_heap(new_block_size);

    // Removing the new free block from the free block list
    pull_free_block(new_block);

    // Copying over the data from just the payload in the original block into
    // the new block
    memmove(new_block->payload, original_block->payload,
            original_size - TAGS_SIZE);

    // Setting the new free block to be allocated
    block_set_allocated(new_block, 1);

    // Freeing the old block
    mm_free(original_block->payload);

    // Returning the payload from the original block
    return new_block->payload;
}

/*
 * checks the state of the heap for internal consistency and prints informative
 * error messages
 * arguments: none
 * returns: 0, if successful
 *          nonzero, if the heap is not consistent
 */
int mm_check_heap(void) {
    if (flist_first != NULL) {
        // Setting free_block to point to the first block within the free list
        block_t *free_block = flist_first;

        // First checking that the first element in free list is marked as free
        if (block_allocated(free_block)) {
            fprintf(stderr, "Flist_first is marked as allocated\n");
            fprintf(stderr, "Block Memory Address: %p\n", (void *)free_block);
            fprintf(stderr, "Block Size: %ld\n", block_size(free_block));
            exit(1);
        }

        // Checking that every element in the free list is marked as free, and
        // that coalescing was not missed for any of free blocks
        free_block = block_next_free(free_block);
        while (free_block != flist_first) {
            // Testing the allocated status of each block in the free list
            if (block_allocated(free_block)) {
                fprintf(stderr, "Block in free list is marked as allocated\n");
                fprintf(stderr, "Block Memory Address: %p\n",
                        (void *)free_block);
                fprintf(stderr, "Block Size: %ld\n", block_size(free_block));
                exit(1);
            }

            // Testing if the previous block is marked as free, indicating
            // that coalescing has failed
            if (block_prev_allocated(free_block) == 0) {
                fprintf(stderr, "Block in free list was not coalesced\n");
                fprintf(stderr, "Block Memory Address: %p\n",
                        (void *)free_block);
                fprintf(stderr, "Block Size: %ld\n", block_size(free_block));
                exit(1);
            }

            // Testing if the next block is marked as free, indicating
            // that coalescing has failed
            if (block_next_allocated(free_block) == 0) {
                fprintf(stderr, "Block in free list was not coalesced\n");
                fprintf(stderr, "Block Memory Address: %p\n",
                        (void *)free_block);
                fprintf(stderr, "Block Size: %ld\n", block_size(free_block));
                exit(1);
            }

            free_block = block_next_free(free_block);
        }
    }

    // Once the above test passes, the heap_checker then tests to ensure that
    // all blocks are currently within the bounds of the heap, and that the end
    // tag matches the beginning tag.

    block_t *first_block = prologue;
    block_t *epilogue_block = epilogue;

    while (first_block != epilogue_block) {
        // Testing if the tags are aligned
        if (block_size(first_block) != align(block_size(first_block))) {
            fprintf(stderr, "Block is incorrectly aligned\n");
            fprintf(stderr, "Block Memory Address: %p\n", (void *)first_block);
            fprintf(stderr, "Block Size: %ld\n", block_size(first_block));
            exit(1);
        }

        // Testing if the first block is before the first heap byte
        if ((void *)first_block < (void *)mem_heap_lo()) {
            fprintf(stderr, "Block is before first heap byte\n");
            fprintf(stderr, "Block Memory Address: %p\n", (void *)first_block);
            fprintf(stderr, "Block Size: %ld\n", block_size(first_block));
            exit(1);
        }

        // Testing if the first block is after the last heap byte
        if ((void *)first_block > (void *)mem_heap_hi()) {
            fprintf(stderr, "Block is after last heap byte\n");
            fprintf(stderr, "Block Memory Address: %p\n", (void *)first_block);
            fprintf(stderr, "Block Size: %ld\n", block_size(first_block));
            exit(1);
        }

        // Testing if the end tag matches the beginning tag
        if (block_allocated(first_block) != block_end_allocated(first_block)) {
            fprintf(stderr, "Block allocation tags do not match\n");
            fprintf(stderr, "Block Memory Address: %p\n", (void *)first_block);
            fprintf(stderr, "Block Size: %ld\n", block_size(first_block));
            exit(1);
        }

        // Testing if the size tag matches the size given in the end tag of the
        // block
        if (block_size(first_block) != block_end_size(first_block)) {
            fprintf(stderr, "Block size tags do not match\n");
            fprintf(stderr, "Block Memory Address: %p\n", (void *)first_block);
            fprintf(stderr, "Block Size: %ld\n", block_size(first_block));
            exit(1);
        }

        // Incrementing the block to point to the next block within the heap
        first_block = block_next(first_block);
    }

    // Returning 0 if all tests passed
    return 0;
}
