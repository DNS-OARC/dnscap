typedef struct _hashitem {
	const void *key;
	void *data;
	struct _hashitem *next;
} hashitem;

typedef unsigned int hashfunc(const void *key);
typedef int hashkeycmp(const void *a, const void *b);
typedef void hashfree(void *);

typedef struct {
	unsigned int modulus;
	hashitem **items;
	hashfunc *hasher;
	hashkeycmp *keycmp;
	hashfree *datafree;
	struct {
		hashitem *next;
		unsigned int slot;
	} iter;
} hashtbl;

hashtbl *hash_create(int N, hashfunc *, hashkeycmp *, hashfree *);
int hash_add(const void *key, void *data, hashtbl *);
void hash_remove(const void *key, hashtbl * tbl);
void *hash_find(const void *key, hashtbl *);
void hash_iter_init(hashtbl *);
void *hash_iterate(hashtbl *);
int hash_count(hashtbl *);
void hash_free(hashtbl *);
void hash_destroy(hashtbl *);

extern unsigned int SuperFastHash (const char * data, int len);
