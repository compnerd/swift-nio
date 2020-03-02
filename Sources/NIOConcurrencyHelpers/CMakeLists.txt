add_library(NIOConcurrencyHelpers
  atomics.swift
  lock.swift
  NIOAtomic.swift)
target_link_libraries(NIOConcurrencyHelpers PRIVATE
  $<$<PLATFORM_ID:Windows>:Winmm>
  CNIOAtomics)
set_target_properties(NIOConcurrencyHelpers PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_Swift_MODULE_DIRECTORY})
