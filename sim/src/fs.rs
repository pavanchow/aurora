//! A small in-memory filesystem built on an inode model.
//!
//! The filesystem has a single root directory. Directories map names to inode
//! numbers. Files hold a byte buffer. Processes open a path to get a file
//! descriptor, then read, write and close it. Paths are absolute and slash
//! separated, for example `/tmp/log`.

use std::collections::HashMap;

/// The kind of object an inode describes.
#[derive(Debug, Clone)]
enum Node {
    Dir(HashMap<String, usize>),
    File(Vec<u8>),
}

/// An inode: type specific content plus a link count.
#[derive(Debug, Clone)]
struct Inode {
    node: Node,
}

/// An open file descriptor: which inode and the current offset.
#[derive(Debug, Clone, Copy)]
struct OpenFile {
    inode: usize,
    offset: usize,
    writable: bool,
}

/// Errors the filesystem can return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsError {
    /// A path component does not exist.
    NotFound,
    /// A path component that should be a directory is a file.
    NotADirectory,
    /// The file descriptor is not open.
    BadFd,
    /// A component already exists when it must not.
    Exists,
}

/// The in-memory filesystem.
#[derive(Debug)]
pub struct FileSystem {
    inodes: Vec<Inode>,
    open: HashMap<usize, OpenFile>,
    next_fd: usize,
    root: usize,
}

impl Default for FileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl FileSystem {
    /// Create a filesystem with an empty root directory.
    pub fn new() -> Self {
        let root = Inode {
            node: Node::Dir(HashMap::new()),
        };
        FileSystem {
            inodes: vec![root],
            open: HashMap::new(),
            next_fd: 0,
            root: 0,
        }
    }

    fn components(path: &str) -> Vec<&str> {
        path.split('/').filter(|s| !s.is_empty()).collect()
    }

    /// Create a directory, creating parents as needed.
    pub fn mkdir(&mut self, path: &str) -> Result<(), FsError> {
        let comps = Self::components(path);
        let mut cur = self.root;
        for name in comps {
            cur = match self.dir_lookup(cur, name) {
                Some(next) => next,
                None => {
                    let idx = self.inodes.len();
                    self.inodes.push(Inode {
                        node: Node::Dir(HashMap::new()),
                    });
                    self.dir_insert(cur, name, idx)?;
                    idx
                }
            };
        }
        Ok(())
    }

    /// Create an empty file, creating parent directories as needed. Returns the
    /// inode number.
    pub fn create(&mut self, path: &str) -> Result<usize, FsError> {
        let comps = Self::components(path);
        if comps.is_empty() {
            return Err(FsError::Exists);
        }
        let (dirs, file) = comps.split_at(comps.len() - 1);
        let mut cur = self.root;
        for name in dirs {
            cur = match self.dir_lookup(cur, name) {
                Some(next) => next,
                None => {
                    let idx = self.inodes.len();
                    self.inodes.push(Inode {
                        node: Node::Dir(HashMap::new()),
                    });
                    self.dir_insert(cur, name, idx)?;
                    idx
                }
            };
        }
        let fname = file[0];
        if let Some(existing) = self.dir_lookup(cur, fname) {
            return Ok(existing);
        }
        let idx = self.inodes.len();
        self.inodes.push(Inode {
            node: Node::File(Vec::new()),
        });
        self.dir_insert(cur, fname, idx)?;
        Ok(idx)
    }

    /// Open a path, creating the file if `create` is set. Returns a file
    /// descriptor.
    pub fn open(&mut self, path: &str, writable: bool, create: bool) -> Result<usize, FsError> {
        let inode = match self.resolve(path) {
            Ok(i) => i,
            Err(FsError::NotFound) if create => self.create(path)?,
            Err(e) => return Err(e),
        };
        let fd = self.next_fd;
        self.next_fd += 1;
        self.open.insert(
            fd,
            OpenFile {
                inode,
                offset: 0,
                writable,
            },
        );
        Ok(fd)
    }

    /// Write bytes at the descriptor's current offset, extending the file as
    /// needed. Returns the number of bytes written.
    pub fn write(&mut self, fd: usize, data: &[u8]) -> Result<usize, FsError> {
        let of = *self.open.get(&fd).ok_or(FsError::BadFd)?;
        if !of.writable {
            return Err(FsError::BadFd);
        }
        let inode = &mut self.inodes[of.inode];
        let buf = match &mut inode.node {
            Node::File(b) => b,
            Node::Dir(_) => return Err(FsError::NotADirectory),
        };
        let end = of.offset + data.len();
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[of.offset..end].copy_from_slice(data);
        self.open.get_mut(&fd).unwrap().offset = end;
        Ok(data.len())
    }

    /// Read up to `len` bytes from the descriptor's current offset.
    pub fn read(&mut self, fd: usize, len: usize) -> Result<Vec<u8>, FsError> {
        let of = *self.open.get(&fd).ok_or(FsError::BadFd)?;
        let inode = &self.inodes[of.inode];
        let buf = match &inode.node {
            Node::File(b) => b,
            Node::Dir(_) => return Err(FsError::NotADirectory),
        };
        let start = of.offset.min(buf.len());
        let end = (of.offset + len).min(buf.len());
        let out = buf[start..end].to_vec();
        self.open.get_mut(&fd).unwrap().offset = end;
        Ok(out)
    }

    /// Close a descriptor.
    pub fn close(&mut self, fd: usize) -> Result<(), FsError> {
        self.open.remove(&fd).map(|_| ()).ok_or(FsError::BadFd)
    }

    /// The size in bytes of the file at a path.
    pub fn size(&self, path: &str) -> Result<usize, FsError> {
        let inode = self.resolve(path)?;
        match &self.inodes[inode].node {
            Node::File(b) => Ok(b.len()),
            Node::Dir(_) => Err(FsError::NotADirectory),
        }
    }

    /// List the entries of a directory, sorted for determinism.
    pub fn list(&self, path: &str) -> Result<Vec<String>, FsError> {
        let inode = if Self::components(path).is_empty() {
            self.root
        } else {
            self.resolve(path)?
        };
        match &self.inodes[inode].node {
            Node::Dir(entries) => {
                let mut names: Vec<String> = entries.keys().cloned().collect();
                names.sort();
                Ok(names)
            }
            Node::File(_) => Err(FsError::NotADirectory),
        }
    }

    fn resolve(&self, path: &str) -> Result<usize, FsError> {
        let comps = Self::components(path);
        let mut cur = self.root;
        for name in comps {
            cur = self.dir_lookup(cur, name).ok_or(FsError::NotFound)?;
        }
        Ok(cur)
    }

    fn dir_lookup(&self, dir: usize, name: &str) -> Option<usize> {
        match &self.inodes[dir].node {
            Node::Dir(entries) => entries.get(name).copied(),
            Node::File(_) => None,
        }
    }

    fn dir_insert(&mut self, dir: usize, name: &str, inode: usize) -> Result<(), FsError> {
        match &mut self.inodes[dir].node {
            Node::Dir(entries) => {
                entries.insert(name.to_string(), inode);
                Ok(())
            }
            Node::File(_) => Err(FsError::NotADirectory),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_write_read_close() {
        let mut fs = FileSystem::new();
        let fd = fs.open("/tmp/log", true, true).unwrap();
        assert_eq!(fs.write(fd, b"hello").unwrap(), 5);
        fs.close(fd).unwrap();

        let fd = fs.open("/tmp/log", false, false).unwrap();
        assert_eq!(fs.read(fd, 5).unwrap(), b"hello");
        fs.close(fd).unwrap();
    }

    #[test]
    fn size_reflects_writes() {
        let mut fs = FileSystem::new();
        let fd = fs.open("/a", true, true).unwrap();
        fs.write(fd, b"1234").unwrap();
        assert_eq!(fs.size("/a").unwrap(), 4);
    }

    #[test]
    fn directories_list_sorted() {
        let mut fs = FileSystem::new();
        fs.mkdir("/etc").unwrap();
        fs.create("/etc/hosts").unwrap();
        fs.create("/etc/passwd").unwrap();
        assert_eq!(fs.list("/etc").unwrap(), vec!["hosts", "passwd"]);
    }

    #[test]
    fn open_missing_without_create_fails() {
        let mut fs = FileSystem::new();
        assert_eq!(fs.open("/nope", false, false), Err(FsError::NotFound));
    }

    #[test]
    fn read_bad_fd_fails() {
        let mut fs = FileSystem::new();
        assert_eq!(fs.read(999, 4), Err(FsError::BadFd));
    }

    #[test]
    fn nested_mkdir_and_resolve() {
        let mut fs = FileSystem::new();
        fs.mkdir("/a/b/c").unwrap();
        fs.create("/a/b/c/file").unwrap();
        assert_eq!(fs.size("/a/b/c/file").unwrap(), 0);
        assert_eq!(fs.list("/a/b").unwrap(), vec!["c"]);
    }
}
