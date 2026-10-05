export class ListNode<T> {
  prev: ListNode<T> | null = null;
  next: ListNode<T> | null = null;
  constructor(public value: T) {}
}

/**
 * Doubly linked list. Invariants (verified by checkIntegrity):
 * head.prev === null, tail.next === null, n.next.prev === n, and a forward walk
 * from head visits exactly `size` nodes and ends at tail.
 */
export class DoublyLinkedList<T> implements Iterable<T> {
  private head: ListNode<T> | null = null;
  private tail: ListNode<T> | null = null;
  private length = 0;

  constructor(values: Iterable<T> = []) {
    for (const value of values) this.append(value);
  }

  get size(): number {
    return this.length;
  }

  get first(): ListNode<T> | null {
    return this.head;
  }

  get last(): ListNode<T> | null {
    return this.tail;
  }

  // Pointer primitives: the only methods allowed to rewire prev/next.
  private linkLast(node: ListNode<T>): void {
    node.prev = this.tail;
    node.next = null;
    if (this.tail) this.tail.next = node;
    else this.head = node;
    this.tail = node;
    this.length++;
  }

  private linkBefore(node: ListNode<T>, ref: ListNode<T>): void {
    node.prev = ref.prev;
    node.next = ref;
    if (ref.prev) ref.prev.next = node;
    else this.head = node;
    ref.prev = node;
    this.length++;
  }

  private unlink(node: ListNode<T>): T {
    if (node.prev) node.prev.next = node.next;
    else this.head = node.next;
    if (node.next) node.next.prev = node.prev;
    else this.tail = node.prev;
    node.prev = node.next = null;
    this.length--;
    return node.value;
  }

  private assertIndex(index: number, max: number): void {
    if (!Number.isInteger(index) || index < 0 || index > max) {
      throw new RangeError(`Index ${index} out of range (size=${this.length})`);
    }
  }

  /** True while the node is still linked into this list. */
  contains(node: ListNode<T>): boolean {
    return node === this.head || (node.prev !== null && node.prev.next === node);
  }

  append(value: T): ListNode<T> {
    const node = new ListNode(value);
    this.linkLast(node);
    return node;
  }

  prepend(value: T): ListNode<T> {
    const node = new ListNode(value);
    if (this.head) this.linkBefore(node, this.head);
    else this.linkLast(node);
    return node;
  }

  insertAt(index: number, value: T): ListNode<T> {
    this.assertIndex(index, this.length);
    if (index === this.length) return this.append(value);
    const node = new ListNode(value);
    this.linkBefore(node, this.nodeAt(index));
    return node;
  }

  /** Walks from the closest end: O(min(i, n - i)). */
  nodeAt(index: number): ListNode<T> {
    this.assertIndex(index, this.length - 1);
    let node: ListNode<T>;
    if (index < this.length / 2) {
      node = this.head!;
      for (let i = 0; i < index; i++) node = node.next!;
    } else {
      node = this.tail!;
      for (let i = this.length - 1; i > index; i--) node = node.prev!;
    }
    return node;
  }

  get(index: number): T {
    return this.nodeAt(index).value;
  }

  removeAt(index: number): T {
    return this.unlink(this.nodeAt(index));
  }

  removeNode(node: ListNode<T>): T {
    if (!this.contains(node)) throw new Error('Node does not belong to this list');
    return this.unlink(node);
  }

  removeWhere(predicate: (value: T) => boolean): number {
    let removed = 0;
    let node = this.head;
    while (node) {
      const following = node.next;
      if (predicate(node.value)) {
        this.unlink(node);
        removed++;
      }
      node = following;
    }
    return removed;
  }

  findNode(predicate: (value: T) => boolean): ListNode<T> | null {
    for (let node = this.head; node; node = node.next) if (predicate(node.value)) return node;
    return null;
  }

  indexOf(predicate: (value: T) => boolean): number {
    let index = 0;
    for (let node = this.head; node; node = node.next, index++) if (predicate(node.value)) return index;
    return -1;
  }

  indexOfNode(target: ListNode<T>): number {
    let index = 0;
    for (let node = this.head; node; node = node.next, index++) if (node === target) return index;
    return -1;
  }

  /**
   * Relinks the node at `from` so it ends up at `to` (same semantics as
   * `arr.splice(to, 0, arr.splice(from, 1)[0])`). No node is created or copied,
   * so external pointers to it (e.g. the playback cursor) stay valid.
   */
  move(from: number, to: number): void {
    this.assertIndex(from, this.length - 1);
    this.assertIndex(to, this.length - 1);
    if (from === to) return;
    const node = this.nodeAt(from);
    this.unlink(node);
    if (to === this.length) this.linkLast(node);
    else this.linkBefore(node, this.nodeAt(to));
  }

  clear(): void {
    let node = this.head;
    while (node) {
      const following = node.next;
      node.prev = node.next = null;
      node = following;
    }
    this.head = this.tail = null;
    this.length = 0;
  }

  toArray(): T[] {
    return [...this];
  }

  *[Symbol.iterator](): Iterator<T> {
    for (let node = this.head; node; node = node.next) yield node.value;
  }

  *reversed(): IterableIterator<T> {
    for (let node = this.tail; node; node = node.prev) yield node.value;
  }

  checkIntegrity(): void {
    if (this.length === 0) {
      if (this.head || this.tail) throw new Error('Empty list must have no head/tail');
      return;
    }
    if (!this.head || !this.tail) throw new Error('Non-empty list needs head and tail');
    if (this.head.prev !== null) throw new Error('head.prev must be null');
    if (this.tail.next !== null) throw new Error('tail.next must be null');
    let count = 0;
    let last: ListNode<T> | null = null;
    for (let node: ListNode<T> | null = this.head; node; node = node.next) {
      if (node.prev !== last) throw new Error(`Broken back-pointer at position ${count}`);
      last = node;
      if (++count > this.length) throw new Error('Cycle detected or size too small');
    }
    if (last !== this.tail) throw new Error('Forward walk must end at tail');
    if (count !== this.length) throw new Error(`Size mismatch: counted ${count}, stored ${this.length}`);
  }
}

/** FIFO queue backed by the doubly linked list: O(1) enqueue and dequeue. */
export class FifoQueue<T> implements Iterable<T> {
  private readonly items = new DoublyLinkedList<T>();

  get size(): number {
    return this.items.size;
  }

  isEmpty(): boolean {
    return this.items.size === 0;
  }

  enqueue(value: T): void {
    this.items.append(value);
  }

  dequeue(): T | undefined {
    return this.items.first ? this.items.removeAt(0) : undefined;
  }

  peek(): T | undefined {
    return this.items.first?.value;
  }

  removeAt(index: number): T {
    return this.items.removeAt(index);
  }

  removeWhere(predicate: (value: T) => boolean): number {
    return this.items.removeWhere(predicate);
  }

  move(from: number, to: number): void {
    this.items.move(from, to);
  }

  clear(): void {
    this.items.clear();
  }

  toArray(): T[] {
    return this.items.toArray();
  }

  [Symbol.iterator](): Iterator<T> {
    return this.items[Symbol.iterator]();
  }

  checkIntegrity(): void {
    this.items.checkIntegrity();
  }
}
