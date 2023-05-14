

/// assert that a type is "plain old data":
/// - no padding,
/// - any bit-pattern is valid
pub unsafe trait Pod {}

unsafe impl Pod for u8 {}
unsafe impl Pod for u16 {}
unsafe impl Pod for u32 {}
unsafe impl Pod for u64 {}
