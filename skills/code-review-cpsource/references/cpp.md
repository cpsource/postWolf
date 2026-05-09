# C++ Code Review Guide

> C++ code review guide focused on memory safety, lifetime, API design, and performance. Examples assume C++17/20.

## Table of Contents

- [Ownership and RAII](#ownership-and-raii)
- [Use-After-Free and Dangling Pointers](#use-after-free-and-dangling-pointers)
- [Null and Unchecked Access](#null-and-unchecked-access)
- [Cast Safety](#cast-safety)
- [Lifetime and References](#lifetime-and-references)
- [Copy and Move Semantics](#copy-and-move-semantics)
- [Const-Correctness and API Design](#const-correctness-and-api-design)
- [Virtual Destructors, Composition, and Modern Keywords](#virtual-destructors-composition-and-modern-keywords)
- [Error Handling and Exception Safety](#error-handling-and-exception-safety)
- [Concurrency](#concurrency)
- [Performance and Allocation](#performance-and-allocation)
- [Templates and Type Safety](#templates-and-type-safety)
- [Tooling and Build Checks](#tooling-and-build-checks)
- [Review Checklist](#review-checklist)

---

## Ownership and RAII

### Prefer RAII and smart pointers

Use RAII to express ownership. Default to `std::unique_ptr`, use `std::shared_ptr` only for shared lifetime.

```cpp
// ? Bad: manual new/delete with early returns
Foo* make_foo() {
    Foo* foo = new Foo();
    if (!foo->Init()) {
        delete foo;
        return nullptr;
    }
    return foo;
}

// ? Good: RAII with unique_ptr
std::unique_ptr<Foo> make_foo() {
    auto foo = std::make_unique<Foo>();
    if (!foo->Init()) {
        return {};
    }
    return foo;
}
```

### Wrap C resources

```cpp
// ? Good: wrap FILE* with unique_ptr
using FilePtr = std::unique_ptr<FILE, decltype(&fclose)>;

FilePtr open_file(const char* path) {
    return FilePtr(fopen(path, "rb"), &fclose);
}
```

---

## Use-After-Free and Dangling Pointers

Even in modern C++, use-after-free can occur when raw pointers, C-style
allocations, or manual `delete` are mixed with RAII types, or when ownership
is transferred incorrectly.

### Pattern 1: Raw delete with remaining aliases

```cpp
// ? Bad: alias survives the delete
auto* raw = new Widget();
Widget* alias = raw;
delete raw;
alias->render(); // UB — use after free
```

### Pattern 2: unique_ptr release or reset with leftover raw pointer

```cpp
// ? Bad: raw pointer dangles after reset
auto owner = std::make_unique<Session>();
Session* cached = owner.get();
owner.reset(); // deletes the Session
cached->run(); // UB — dangling
```

### Pattern 3: Container invalidation

```cpp
// ? Bad: iterator/pointer invalidated by push_back
std::vector<int> v = {1, 2, 3};
int* p = &v[0];
v.push_back(4); // may reallocate
*p = 42;        // UB if reallocation occurred

// ? Good: re-obtain pointer after mutation
v.push_back(4);
p = &v[0]; // safe
```

### Pattern 4: Moved-from object access

```cpp
// ? Bad: using a moved-from string
std::string name = "hello";
std::string other = std::move(name);
std::cout << name.size(); // valid but surprising — moved-from state
name[0] = 'H';            // may be UB if string is now empty
```

### Pattern 5: Shared pointer cycles and weak pointer expiry

```cpp
// ? Bad: weak_ptr not checked before use
std::weak_ptr<Resource> weak = shared;
shared.reset();
auto locked = weak.lock();
// locked is nullptr — must check before dereferencing
locked->use(); // null deref if not checked
```

### Pattern 6: C-library or legacy code mixed with C++ RAII

When a codebase mixes C-style `malloc`/`free`/`XFREE` with C++ objects, the
same patterns from the C guide apply. Pay special attention to:

- `memcpy` of structs containing raw pointers, followed by freeing the source
- Callback-based APIs that store raw `this` pointers — if the C++ object is
  destroyed before the callback fires, the pointer dangles
- C cleanup functions (`goto cleanup` patterns) that free memory still
  referenced by C++ containers or smart pointers in the same scope

### What to look for during review

- Every `delete`/`reset()`/`release()`: trace all raw pointers and references
  to the same object forward — are any used after the delete?
- Every `std::move()`: is the moved-from object accessed afterward beyond
  querying its empty/valid state?
- Every `push_back`/`insert`/`erase` on containers: are there iterators,
  pointers, or references that were obtained before the mutation?
- Every `.get()` on a `unique_ptr` or `shared_ptr`: does the raw pointer
  outlive the smart pointer's ownership?
- Every weak_ptr: is `lock()` checked for nullptr before use?
- Mixed C/C++ code: is `free`/`XFREE` called on memory that C++ RAII types
  also claim ownership of?

---

## Null and Unchecked Access

Null pointer dereference and unchecked optional/expected access are common
crash bugs in C++.

### Pattern 1: Unchecked pointer parameter

```cpp
// ? Bad: no null check
void process(Widget* w) {
    w->run();  // crashes if w is nullptr
}

// ? Good: check or use a reference to express non-null
void process(Widget& w) {
    w.run();  // reference can't be null (by convention)
}
```

### Pattern 2: Unchecked std::optional access

```cpp
// ? Bad: .value() throws if empty, *opt is UB if empty
std::optional<int> result = find(key);
int v = *result;  // UB if result is std::nullopt

// ? Good: check before access
if (result.has_value()) {
    int v = *result;
}
// or use value_or
int v = result.value_or(0);
```

### Pattern 3: Unchecked dynamic_cast

```cpp
// ? Bad: dynamic_cast to pointer returns nullptr on failure
Base* base = get_object();
Derived* d = dynamic_cast<Derived*>(base);
d->specific_method();  // null deref if base is not Derived

// ? Good: check the result
if (auto* d = dynamic_cast<Derived*>(base)) {
    d->specific_method();
}
```

### Pattern 4: Unchecked map/container lookup

```cpp
// ? Bad: operator[] inserts default if key missing (for map) or UB (for unordered_map iterators)
auto it = map.find(key);
use(it->second);  // UB if it == map.end()

// ? Good: check iterator
if (auto it = map.find(key); it != map.end()) {
    use(it->second);
}
```

### What to look for during review

- Every raw pointer parameter: can it be nullptr? Should it be a reference?
- Every `std::optional`: is `.value()` or `*` used without checking?
- Every `dynamic_cast<T*>`: is the result checked for nullptr?
- Every `map.find()` / `set.find()`: is the iterator compared to `.end()`?
- Every function returning a pointer: do callers check for null?

---

## Cast Safety

C++ provides typed casts, but they can still be misused.

### Pattern 1: C-style cast hiding dangerous conversions

```cpp
// ? Bad: C-style cast silently does reinterpret_cast
void* data = get_data();
Widget* w = (Widget*)data;  // no type checking

// ? Good: use static_cast (checked at compile time) or explicit design
Widget* w = static_cast<Widget*>(data);
```

### Pattern 2: const_cast then write

```cpp
// ? Bad: casting away const and writing is UB if original was const
void modify(const std::string& s) {
    auto& mut = const_cast<std::string&>(s);
    mut.clear();  // UB if s refers to a truly const object
}
```

### Pattern 3: reinterpret_cast for type punning

```cpp
// ? Bad: strict aliasing violation
float f = 3.14f;
int i = *reinterpret_cast<int*>(&f);  // UB

// ? Good: use std::bit_cast (C++20) or memcpy
int i = std::bit_cast<int>(f);
```

### What to look for during review

- Every C-style cast `(Type)expr`: replace with the appropriate C++ cast
- Every `const_cast`: why is it needed? Is the underlying data actually mutable?
- Every `reinterpret_cast`: is it for type punning (use `bit_cast`/`memcpy`),
  or for a legitimate byte-level operation?
- Every `static_cast` between pointer types: is the conversion valid?

---

## Lifetime and References

### Avoid dangling references and views

`std::string_view` and `std::span` do not own data. Make sure the owner outlives the view.

```cpp
// ? Bad: returning string_view to a temporary
std::string_view bad_view() {
    std::string s = make_name();
    return s; // dangling
}

// ? Good: return owning string
std::string good_name() {
    return make_name();
}

// ? Good: view tied to caller-owned data
std::string_view good_view(const std::string& s) {
    return s;
}
```

### Lambda captures

```cpp
// ? Bad: capture reference that escapes
std::function<void()> make_task() {
    int value = 42;
    return [&]() { use(value); }; // dangling
}

// ? Good: capture by value
std::function<void()> make_task() {
    int value = 42;
    return [value]() { use(value); };
}
```

---

## Copy and Move Semantics

### Rule of 0/3/5

Prefer the Rule of 0 by using RAII types. If you own a resource, define or delete copy and move operations.

```cpp
// ? Bad: raw ownership with default copy
struct Buffer {
    int* data;
    size_t size;
    explicit Buffer(size_t n) : data(new int[n]), size(n) {}
    ~Buffer() { delete[] data; }
    // copy ctor/assign are implicitly generated -> double delete
};

// ? Good: Rule of 0 with std::vector
struct Buffer {
    std::vector<int> data;
    explicit Buffer(size_t n) : data(n) {}
};
```

### Delete unwanted copies

```cpp
struct Socket {
    Socket() = default;
    ~Socket() { close(); }

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&&) noexcept = default;
    Socket& operator=(Socket&&) noexcept = default;
};
```

---

## Const-Correctness and API Design

### Use const and explicit

```cpp
class User {
public:
    const std::string& name() const { return name_; }
    void set_name(std::string name) { name_ = std::move(name); }

private:
    std::string name_;
};

struct Millis {
    explicit Millis(int v) : value(v) {}
    int value;
};
```

### Avoid object slicing

```cpp
struct Shape { virtual ~Shape() = default; };
struct Circle : Shape { void draw() const; };

// ? Bad: slices Circle into Shape
void draw(Shape shape);

// ? Good: pass by reference
void draw(const Shape& shape);
```

### Use override and final

```cpp
struct Base {
    virtual void run() = 0;
};

struct Worker final : Base {
    void run() override {}
};
```

### Virtual destructors for polymorphic types

```cpp
// ? Bad: deleting Derived through Base* is UB without virtual dtor
struct Base {
    void run();
    ~Base();  // non-virtual
};
struct Derived : Base { std::vector<int> data; };

Base* p = new Derived();
delete p;  // UB — Derived destructor not called, data leaked

// ? Good: virtual destructor if any virtual function or polymorphic deletion
struct Base {
    virtual ~Base() = default;
};
```

Rule: if a class has any virtual function, it should have a virtual destructor.
If a class is not meant to be inherited, mark it `final`.

### Prefer composition over inheritance

```cpp
// ? Fragile: tight coupling to base class implementation
struct Logger : public FileWriter {
    void log(const std::string& msg) { write(msg + "\n"); }
};

// ? Better: composition — easier to change, test, and reason about
struct Logger {
    explicit Logger(std::unique_ptr<Writer> w) : writer_(std::move(w)) {}
    void log(const std::string& msg) { writer_->write(msg + "\n"); }
private:
    std::unique_ptr<Writer> writer_;
};
```

Use inheritance for true "is-a" relationships with virtual dispatch. Use
composition for "has-a" or "uses-a" relationships.

### noexcept, explicit, and constexpr

```cpp
// ? Good: move operations should be noexcept (enables optimizations)
Buffer(Buffer&& other) noexcept;
Buffer& operator=(Buffer&& other) noexcept;

// ? Good: single-argument constructors should be explicit
explicit Widget(int id);

// ? Good: constexpr for compile-time evaluation where possible
constexpr size_t max_size() { return 1024; }
```

- `noexcept`: required on move operations for `std::vector` to use moves
  during reallocation. Also on swap and destructors.
- `explicit`: prevents implicit conversions that hide bugs.
- `constexpr`: prefer for constants and simple functions that can be evaluated
  at compile time.

---

## Error Handling and Exception Safety

### Prefer RAII for cleanup

```cpp
// ? Good: RAII handles cleanup on exceptions
void process() {
    std::vector<int> data = load_data(); // safe cleanup
    do_work(data);
}
```

### Do not throw from destructors

```cpp
struct File {
    ~File() noexcept { close(); }
    void close();
};
```

### Use expected results for normal failures

```cpp
// ? Expected error: use optional or expected
std::optional<int> parse_int(const std::string& s) {
    try {
        return std::stoi(s);
    } catch (...) {
        return std::nullopt;
    }
}
```

---

## Concurrency

### Protect shared data

```cpp
// ? Bad: data race
int counter = 0;
void inc() { counter++; }

// ? Good: atomic
std::atomic<int> counter{0};
void inc() { counter.fetch_add(1, std::memory_order_relaxed); }
```

### Use RAII locks

```cpp
std::mutex mu;
std::vector<int> data;

void add(int v) {
    std::lock_guard<std::mutex> lock(mu);
    data.push_back(v);
}
```

### Consistent lock ordering

```cpp
// ? Bad: thread 1 locks A then B, thread 2 locks B then A — deadlock
void thread1() { lock(mu_a); lock(mu_b); /* ... */ }
void thread2() { lock(mu_b); lock(mu_a); /* ... */ }

// ? Good: always lock in the same order, or use std::scoped_lock
void safe() {
    std::scoped_lock lock(mu_a, mu_b);  // deadlock-free
}
```

### Check-then-act races

```cpp
// ? Bad: map may be modified between find and use
if (map.find(key) != map.end()) {
    use(map[key]);  // another thread may erase key between check and use
}

// ? Good: hold lock across check and use, or use atomic operations
std::lock_guard lock(mu);
if (auto it = map.find(key); it != map.end()) {
    use(it->second);
}
```

### Condition variable spurious wakeup

```cpp
// ? Bad: no predicate re-check — may proceed on spurious wakeup
cv.wait(lock);

// ? Good: always re-check the predicate
cv.wait(lock, [&] { return ready; });
```

### What to look for

- Every shared variable: protected by mutex or atomic?
- Every mutex pair: always acquired in the same order?
- Every condition_variable::wait: has a predicate?
- Callbacks or virtual calls while holding a lock: can they deadlock?
- Thread shutdown: are all threads joined or detached before destruction?
- Reference counts (`shared_ptr`, custom refcounts): updates atomic?

---

## Performance and Allocation

### Avoid repeated allocations

```cpp
// ? Bad: repeated reallocation
std::vector<int> build(int n) {
    std::vector<int> out;
    for (int i = 0; i < n; ++i) {
        out.push_back(i);
    }
    return out;
}

// ? Good: reserve upfront
std::vector<int> build(int n) {
    std::vector<int> out;
    out.reserve(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        out.push_back(i);
    }
    return out;
}
```

### String concatenation

```cpp
// ? Bad: repeated allocation
std::string join(const std::vector<std::string>& parts) {
    std::string out;
    for (const auto& p : parts) {
        out += p;
    }
    return out;
}

// ? Good: reserve total size
std::string join(const std::vector<std::string>& parts) {
    size_t total = 0;
    for (const auto& p : parts) {
        total += p.size();
    }
    std::string out;
    out.reserve(total);
    for (const auto& p : parts) {
        out += p;
    }
    return out;
}
```

---

## Templates and Type Safety

### Prefer constrained templates (C++20)

```cpp
// ? Bad: overly generic
template <typename T>
T add(T a, T b) {
    return a + b;
}

// ? Good: constrained
template <typename T>
requires std::is_integral_v<T>
T add(T a, T b) {
    return a + b;
}
```

### Use static_assert for invariants

```cpp
template <typename T>
struct Packet {
    static_assert(std::is_trivially_copyable_v<T>,
        "Packet payload must be trivially copyable");
    T payload;
};
```

---

## Tooling and Build Checks

```bash
# Warnings
clang++ -Wall -Wextra -Werror -Wconversion -Wshadow -std=c++20 ...

# Sanitizers (debug builds)
clang++ -fsanitize=address,undefined -fno-omit-frame-pointer -g ...
clang++ -fsanitize=thread -fno-omit-frame-pointer -g ...

# Static analysis
clang-tidy src/*.cpp -- -std=c++20

# Formatting
clang-format -i src/*.cpp include/*.h
```

---

## Review Checklist

### Safety and Lifetime
- [ ] Ownership is explicit (RAII, unique_ptr by default)
- [ ] No dangling references or views
- [ ] Rule of 0/3/5 followed for resource-owning types
- [ ] No raw new/delete in business logic
- [ ] Destructors are noexcept and do not throw
- [ ] No use-after-free: every `delete`/`reset()`/`release()` traced forward
- [ ] No dangling raw pointers from `.get()` that outlive the smart pointer
- [ ] No container invalidation: iterators/pointers revalidated after mutation
- [ ] No access to moved-from objects beyond checking empty/valid state
- [ ] `weak_ptr::lock()` checked for nullptr before dereference
- [ ] Mixed C/C++ code: no double ownership between `free` and RAII destructors

### Null and Unchecked Access
- [ ] Raw pointer parameters checked for nullptr (or use references for non-null)
- [ ] `std::optional` checked with `has_value()` before `.value()` or `*`
- [ ] `dynamic_cast<T*>` result checked for nullptr
- [ ] Map/set `find()` iterators compared to `.end()` before dereference
- [ ] Functions returning pointers: callers check for null

### Cast Safety
- [ ] No C-style casts — use `static_cast`/`dynamic_cast`/`reinterpret_cast`
- [ ] `const_cast`: justified and underlying data is actually mutable
- [ ] `reinterpret_cast`: not used for type punning (use `bit_cast`/`memcpy`)
- [ ] `static_cast` between pointer types: conversion is valid

### API and Design
- [ ] const-correctness is applied consistently
- [ ] Constructors are explicit where needed
- [ ] Override/final used for virtual functions
- [ ] No object slicing (pass by ref or pointer)
- [ ] Virtual destructors on all polymorphic base classes
- [ ] Composition preferred over inheritance unless true "is-a"
- [ ] `noexcept` on move operations, swap, and destructors
- [ ] `constexpr` used where compile-time evaluation is possible
- [ ] Interface minimal and hard to misuse

### Error Handling
- [ ] Exceptions used safely and consistently (not mixed with error codes)
- [ ] No exceptions from destructors
- [ ] Assertions not used for runtime error handling
- [ ] Errors propagated with enough context

### Concurrency
- [ ] Shared data is protected (mutex or atomics)
- [ ] Lock acquisition order consistent across all code paths
- [ ] No blocking or callbacks while holding locks
- [ ] `condition_variable::wait` always has a predicate (spurious wakeup)
- [ ] No check-then-act races on shared state
- [ ] All threads joined or detached before owning object destruction
- [ ] `shared_ptr` and custom refcounts: updates are atomic

### Performance
- [ ] Unnecessary allocations avoided (reserve, move)
- [ ] Copies avoided in hot paths
- [ ] Algorithmic complexity is reasonable
- [ ] No accidental quadratic behavior
- [ ] Data structures appropriate for expected sizes and operations

### Tooling and Tests
- [ ] Builds clean with warnings enabled
- [ ] Sanitizers run on critical code paths
- [ ] Static analysis (clang-tidy) results are addressed
