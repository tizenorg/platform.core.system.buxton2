# example build

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/lib/include)

ADD_EXECUTABLE(get_sync get_sync.c)
TARGET_LINK_LIBRARIES(get_sync buxton2)

ADD_EXECUTABLE(get_async get_async.c)
TARGET_LINK_LIBRARIES(get_async buxton2)

ADD_EXECUTABLE(set_sync set_sync.c)
TARGET_LINK_LIBRARIES(set_sync buxton2)

ADD_EXECUTABLE(set_async set_async.c)
TARGET_LINK_LIBRARIES(set_async buxton2)

