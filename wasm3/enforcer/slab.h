//  Copyright 2022 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SLAB_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SLAB_H_

#include <memory>
#include <vector>

#include "third_party/sealedcomputing/wasm3/logging.h"

namespace sealed {
namespace wasm {

namespace slab {

static uint16_t next_slab_number_ = 0;

}  // namespace slab

template <class T, class Deleter = std::default_delete<T>>
class Slab {
 private:
  // An internal node in the slab that holds the data and the freelist.
  struct SlabNode {
    T* data;
    // The index of the next empty node if empty otherwise kEmptyIndex.
    uint32_t next_index = -1;
    // A unique counter so we can verify we are given a valid SlabPtr.
    uint16_t ctr;
    bool empty = false;
    inline void check_empty() const { SC_CHECK(empty) << "Slab is not empty"; }
    inline void check_not_empty(uint16_t expected_ctr) const {
      SC_CHECK(!empty) << "Slab is empty";
      SC_CHECK_EQ(ctr, expected_ctr) << "Invalid ctr";
    }
  };

 public:
  // A pointer to an opaque object inside the Slab.
  struct SlabPtr {
    // An index into the vector of the Slab.
    uint32_t p;
    // A unique counter so SlabPtr to the same index don't collide.
    uint16_t ctr;
    // The id of the parent Slab so it can't be used in the wrong Slab.
    uint16_t slab_number;
    inline int64_t Serialize() const {
      return static_cast<int64_t>(static_cast<uint64_t>(p) << 32 |
                                  static_cast<uint64_t>(ctr) << 16 |
                                  static_cast<uint64_t>(slab_number));
    }
    static inline SlabPtr Deserialize(int64_t data) {
      uint64_t u_data = static_cast<uint64_t>(data);
      // TODO: sanitize u_data >> 32 before using as index into vector (line 85)
      return SlabPtr{static_cast<uint32_t>(u_data >> 32),
                     static_cast<uint16_t>(u_data >> 16),
                     static_cast<uint16_t>(u_data)};
    }
  };

  Slab() : slab_number_(slab::next_slab_number_++), deleter_(Deleter()) {}

  Slab(const Deleter& deleter)
      : deleter_(deleter), slab_number_(slab::next_slab_number_++) {}

  ~Slab() {
    for (const SlabNode& node : slab_) {
      node.check_empty();
    }
  }

  // Create a SlabPtr of the given data, giving ownership to the Slab.
  const SlabPtr Create(T* data) {
    SlabPtr ptr{next_free_, slab_ptr_ctr_++, slab_number_};
    if (next_free_ == slab_.size()) {
      SlabNode node;
      node.data = data;
      node.ctr = ptr.ctr;
      node.empty = false;
      slab_.push_back(node);
      next_free_++;
    } else {
      FreeListPop(ptr, data);
    }
    return ptr;
  }

  const SlabPtr Create(T&& data) { return Create(new T(data)); }

  const SlabPtr Create(T& data) { return Create(std::move(data)); }

  // Get the data associated with the given SlabPtr.
  // The Slab still maintains ownership.
  T* Get(SlabPtr ptr) const {
    SC_CHECK_EQ(slab_number_, ptr.slab_number) << "Invalid slab number";
    SC_CHECK_LT(ptr.p, slab_.size()) << "Invalid slab index";
    const SlabNode& node = slab_[ptr.p];
    node.check_not_empty(ptr.ctr);
    return node.data;
  }

  T* Get(int64_t serialized_ptr) const {
    return Get(SlabPtr::Deserialize(serialized_ptr));
  }

  // Destroys the data associated with the given SlabPtr.
  void Destroy(SlabPtr ptr) {
    SC_CHECK_EQ(slab_number_, ptr.slab_number) << "Invalid slab number";
    SC_CHECK_LT(ptr.p, slab_.size()) << "Invalid slab index";
    FreeListPush(ptr);
  }

  void Destroy(int64_t serialized_ptr) {
    Destroy(SlabPtr::Deserialize(serialized_ptr));
  }

 private:
  SlabNode* FreeListPop(const SlabPtr& ptr, T* data) {
    SlabNode* node = &slab_[next_free_];
    node->check_empty();
    node->ctr = ptr.ctr;
    node->data = data;
    node->empty = false;
    next_free_ = node->next_index;
    return node;
  }

  SlabNode* FreeListPush(const SlabPtr& ptr) {
    SlabNode* node = &slab_[ptr.p];
    node->check_not_empty(ptr.ctr);
    node->next_index = next_free_;
    next_free_ = ptr.p;
    deleter_(node->data);
    node->empty = true;
    return node;
  }

  // A unique id for each Slab.
  const uint16_t slab_number_;
  // The function to use to delete SlabNode data when destroyed.
  const Deleter deleter_;
  // The index of the next empty slot.
  uint32_t next_free_ = 0;
  // A counter so each SlabPtr is unique.
  uint16_t slab_ptr_ctr_ = 0;
  // Allocated memory for SlabNodes.
  std::vector<SlabNode> slab_;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SLAB_H_
