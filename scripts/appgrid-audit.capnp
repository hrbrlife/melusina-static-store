@0xe27d54e5861f0acd;

# Deliberately narrow read-only projection of Sandstorm's package Archive.
# Field ordinals match package.capnp; it exists so the icon generator can
# inspect only the signed manifest payload without unpacking a package tree.

struct ArchiveProjection {
  files @0 :List(FileProjection);

  struct FileProjection {
    name @0 :Text;
    lastModificationTimeNs @5 :Int64;
    union {
      regular @1 :Data;
      executable @2 :Void;
      symlink @3 :Void;
      directory @4 :Void;
    }
  }
}
