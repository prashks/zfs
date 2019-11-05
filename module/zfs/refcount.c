/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2015, 2019 by Delphix. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/refcount.h>

#ifdef _KERNEL
int reference_tracking_enable = FALSE; /* runs out of memory too easily */
#else
int reference_tracking_enable = TRUE;
#endif
int reference_history = 3; /* tunable */

#ifdef	ZFS_DEBUG
static kmem_cache_t *reference_cache;
static kmem_cache_t *reference_history_cache;

void
zfs_refcount_init(void)
{
	reference_cache = kmem_cache_create("reference_cache",
	    sizeof (reference_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	reference_history_cache = kmem_cache_create("reference_history_cache",
	    sizeof (uint64_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
}

void
zfs_refcount_fini(void)
{
	kmem_cache_destroy(reference_cache);
	kmem_cache_destroy(reference_history_cache);
}

static int
zfs_refcount_compare(const void *l, const void *r)
{
	const reference_t *lrefn = l;
	const reference_t *rrefn = r;

	int64_t cmp = TREE_CMP(lrefn->ref_holder, rrefn->ref_holder);
	if (likely(cmp))
		return (cmp);
	cmp = TREE_CMP(lrefn->ref_number, rrefn->ref_number);
	if (likely(cmp))
		return (cmp);
	return (TREE_ISIGN(cmp));
}

void
zfs_refcount_create(zfs_refcount_t *rc)
{
	mutex_init(&rc->rc_mtx, NULL, MUTEX_DEFAULT, NULL);
	avl_create(&rc->rc_list, zfs_refcount_compare,
	    sizeof (reference_t),
	    offsetof(reference_t, ref_link));
	avl_create(&rc->rc_removed, zfs_refcount_compare,
	    sizeof (reference_t),
	    offsetof(reference_t, ref_link));
	rc->rc_count = 0;
	rc->rc_removed_count = 0;
	rc->rc_tracked = reference_tracking_enable;
}

void
zfs_refcount_create_tracked(zfs_refcount_t *rc)
{
	zfs_refcount_create(rc);
	rc->rc_tracked = B_TRUE;
}

void
zfs_refcount_create_untracked(zfs_refcount_t *rc)
{
	zfs_refcount_create(rc);
	rc->rc_tracked = B_FALSE;
}

void
zfs_refcount_destroy_many(zfs_refcount_t *rc, uint64_t number)
{
	reference_t *ref;

	ASSERT3U(rc->rc_count, ==, number);
	// XXX - better way to walk ?
	while ((ref = avl_first(&rc->rc_list))) {
		avl_remove(&rc->rc_list, ref);
		kmem_cache_free(reference_cache, ref);
	}
	avl_destroy(&rc->rc_list);

	while ((ref = avl_first(&rc->rc_removed))) {
		avl_remove(&rc->rc_removed, ref);
		kmem_cache_free(reference_history_cache, ref->ref_removed);
		kmem_cache_free(reference_cache, ref);
	}
	avl_destroy(&rc->rc_removed);
	mutex_destroy(&rc->rc_mtx);
}

void
zfs_refcount_destroy(zfs_refcount_t *rc)
{
	zfs_refcount_destroy_many(rc, 0);
}

int
zfs_refcount_is_zero(zfs_refcount_t *rc)
{
	return (rc->rc_count == 0);
}

int64_t
zfs_refcount_count(zfs_refcount_t *rc)
{
	return (rc->rc_count);
}

int64_t
zfs_refcount_add_many(zfs_refcount_t *rc, uint64_t number, const void *holder)
{
	reference_t *ref = NULL;
	int64_t count;

	if (rc->rc_tracked) {
		ref = kmem_cache_alloc(reference_cache, KM_SLEEP);
		ref->ref_holder = holder;
		ref->ref_number = number;
	}
	mutex_enter(&rc->rc_mtx);
	ASSERT3U(rc->rc_count, >=, 0);
	if (rc->rc_tracked)
		avl_add(&rc->rc_list, ref);
	rc->rc_count += number;
	count = rc->rc_count;
	mutex_exit(&rc->rc_mtx);

	return (count);
}

int64_t
zfs_refcount_add(zfs_refcount_t *rc, const void *holder)
{
	return (zfs_refcount_add_many(rc, 1, holder));
}

int64_t
zfs_refcount_remove_many(zfs_refcount_t *rc, uint64_t number,
    const void *holder)
{
	reference_t ref_search;
	reference_t *ref = NULL;
	avl_index_t where;
	int64_t count;

	mutex_enter(&rc->rc_mtx);
	ASSERT3U(rc->rc_count, >=, number);

	if (!rc->rc_tracked) {
		rc->rc_count -= number;
		count = rc->rc_count;
		mutex_exit(&rc->rc_mtx);
		return (count);
	}

	ref_search.ref_number = number;
	ref_search.ref_holder = holder;
	ref = avl_find(&rc->rc_list, &ref_search, &where);
	if (ref != NULL) { // XXX: might also need to use avl_nearest ?
		avl_remove(&rc->rc_list, ref);
		if (reference_history > 0) {
			ref->ref_removed =
			    kmem_cache_alloc(reference_history_cache,
			    KM_SLEEP);
			avl_insert(&rc->rc_removed, ref, where);
			rc->rc_removed_count++;
			if (rc->rc_removed_count > reference_history) {
				ref = avl_last(&rc->rc_removed);
				avl_remove(&rc->rc_removed, ref);
				kmem_cache_free(reference_history_cache,
				    ref->ref_removed);
				kmem_cache_free(reference_cache, ref);
				rc->rc_removed_count--;
			}
		} else {
			kmem_cache_free(reference_cache, ref);
		}
		rc->rc_count -= number;
		count = rc->rc_count;
		mutex_exit(&rc->rc_mtx);
		return (count);
	}
	panic("No such hold %p on refcount %llx", holder,
	    (u_longlong_t)(uintptr_t)rc);
	return (-1);
}

int64_t
zfs_refcount_remove(zfs_refcount_t *rc, const void *holder)
{
	return (zfs_refcount_remove_many(rc, 1, holder));
}

void
zfs_refcount_transfer(zfs_refcount_t *dst, zfs_refcount_t *src)
{
	int64_t count, removed_count;
	avl_tree_t list, removed;
	reference_t *ref, *ref_next;

	avl_create(&list, zfs_refcount_compare,
	    sizeof (reference_t), offsetof(reference_t, ref_link));
	avl_create(&removed, zfs_refcount_compare,
	    sizeof (reference_t), offsetof(reference_t, ref_link));

	mutex_enter(&src->rc_mtx);
	count = src->rc_count;
	removed_count = src->rc_removed_count;
	src->rc_count = 0;
	src->rc_removed_count = 0;
	// XXX: list_move_tail(&list, &src->rc_list); theres better way to do this
	for (ref = avl_first(&src->rc_list); ref != NULL; ref = ref_next) {
		ref_next = AVL_NEXT(&src->rc_list, ref);
		avl_add(&list, ref);
	}

	// XXX: list_move_tail(&removed, &src->rc_removed);
	for (ref = avl_first(&src->rc_removed); ref != NULL; ref = ref_next) {
		ref_next = AVL_NEXT(&src->rc_removed, ref);
		avl_add(&removed, ref);
	}

	mutex_exit(&src->rc_mtx);

	mutex_enter(&dst->rc_mtx);
	dst->rc_count += count;
	dst->rc_removed_count += removed_count;
	// XXX: list_move_tail(&dst->rc_list, &list);
	for (ref = avl_first(&list); ref != NULL; ref = ref_next) {
		ref_next = AVL_NEXT(&list, ref);
		avl_add(&dst->rc_list, ref);
	}
	// XXX: list_move_tail(&dst->rc_removed, &removed);
	for (ref = avl_first(&removed); ref != NULL; ref = ref_next) {
		ref_next = AVL_NEXT(&removed, ref);
		avl_add(&dst->rc_removed, ref);
	}
	mutex_exit(&dst->rc_mtx);

	avl_destroy(&list);
	avl_destroy(&removed);
}

void
zfs_refcount_transfer_ownership_many(zfs_refcount_t *rc, uint64_t number,
    const void *current_holder, const void *new_holder)
{
	boolean_t found = B_FALSE;
	reference_t *ref = NULL;
	reference_t ref_search;
	avl_index_t where;

	mutex_enter(&rc->rc_mtx);
	if (!rc->rc_tracked) {
		mutex_exit(&rc->rc_mtx);
		return;
	}

	ref_search.ref_number = number;
	ref_search.ref_holder = current_holder;
	ref = avl_find(&rc->rc_list, &ref_search, &where);
	if (ref != NULL) { // XXX: might also need to use avl_nearest ?
		ref->ref_holder = new_holder;
		found = B_TRUE;
	}
	ASSERT(found);
	mutex_exit(&rc->rc_mtx);
}

void
zfs_refcount_transfer_ownership(zfs_refcount_t *rc, const void *current_holder,
    const void *new_holder)
{
	return (zfs_refcount_transfer_ownership_many(rc, 1, current_holder,
	    new_holder));
}

/*
 * If tracking is enabled, return true if a reference exists that matches
 * the "holder" tag. If tracking is disabled, then return true if a reference
 * might be held.
 */
boolean_t
zfs_refcount_held(zfs_refcount_t *rc, const void *holder)
{
	reference_t *ref = NULL;
	reference_t ref_search;
	avl_index_t where;

	mutex_enter(&rc->rc_mtx);

	if (!rc->rc_tracked) {
		mutex_exit(&rc->rc_mtx);
		return (rc->rc_count > 0);
	}

	ref_search.ref_number = rc->rc_count; // XXX - will rc_count be valid ?
	ref_search.ref_holder = holder;
	ref = avl_find(&rc->rc_list, &ref_search, &where);
	if (ref != NULL) { // XXX: might also need to use avl_nearest ?
		mutex_exit(&rc->rc_mtx);
		return (B_TRUE);
	}
	mutex_exit(&rc->rc_mtx);
	return (B_FALSE);
}

/*
 * If tracking is enabled, return true if a reference does not exist that
 * matches the "holder" tag. If tracking is disabled, always return true
 * since the reference might not be held.
 */
boolean_t
zfs_refcount_not_held(zfs_refcount_t *rc, const void *holder)
{
	reference_t *ref = NULL;
	reference_t ref_search;
	avl_index_t where;

	mutex_enter(&rc->rc_mtx);

	if (!rc->rc_tracked) {
		mutex_exit(&rc->rc_mtx);
		return (B_TRUE);
	}

	ref_search.ref_number = rc->rc_count; // XXX - will rc_count be valid ?
	ref_search.ref_holder = holder;
	ref = avl_find(&rc->rc_list, &ref_search, &where);
	if (ref != NULL) { // XXX: might also need to use avl_nearest ?
		mutex_exit(&rc->rc_mtx);
		return (B_FALSE);
	}
	mutex_exit(&rc->rc_mtx);
	return (B_TRUE);
}
#endif	/* ZFS_DEBUG */
