# - Find mtree
# Find the MTree include directory and library
#
#  MTREE_INCLUDE_DIR    - where to find mtree.h, etc.
#  MTREE_LIBRARIES      - List of libraries when using libmtree.
#  MTREE_FOUND          - True if libmtree found.

IF (MTREE_INCLUDE_DIR)
  # Already in cache, be silent
  SET(MTREE_FIND_QUIETLY TRUE)
ENDIF (MTREE_INCLUDE_DIR)

FIND_PATH(MTREE_INCLUDE_DIR mtree.h)
FIND_LIBRARY(MTREE_LIBRARY NAMES mtree libmtree)

# handle the QUIETLY and REQUIRED arguments and set LIBMTREE_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(MTREE DEFAULT_MSG MTREE_LIBRARY MTREE_INCLUDE_DIR)

IF(MTREE_FOUND)
  SET(MTREE_LIBRARIES ${MTREE_LIBRARY})
ENDIF(MTREE_FOUND)
