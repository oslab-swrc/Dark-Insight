// TC_OUT
0000000000d44db0 <XXH64_digest_endian>:
  d44db0:	push   %rbp
  d44db1:	lea    0x30(%rdi),%rax
  d44db5:	mov    %rsp,%rbp
  d44db8:	push   %r13
  d44dba:	push   %r12
  d44dbc:	push   %rbx
  d44dbd:	mov    0x50(%rdi),%r8d
  d44dc1:	mov    (%rdi),%r9
  d44dc4:	add    %rax,%r8
  d44dc7:	cmp    $0x1f,%r9
  d44dcb:	jbe    d44fb8 <XXH64_digest_endian+0x208>
  d44dd1:	mov    0x10(%rdi),%r12
  d44dd5:	mov    0x18(%rdi),%rbx
  d44dd9:	movabs $0xc2b2ae3d27d4eb4f,%r10
  d44de3:	mov    0x20(%rdi),%r11
  d44de7:	mov    0x28(%rdi),%r13
  d44deb:	mov    %rbx,%rcx
  d44dee:	mov    %r12,%rdx
  d44df1:	ror    $0x3f,%rdx
  d44df5:	ror    $0x39,%rcx
  d44df9:	add    %rdx,%rcx
  d44dfc:	mov    %r11,%rdx
  d44dff:	imul   %r10,%r12
  d44e03:	ror    $0x34,%rdx
  d44e07:	add    %rdx,%rcx
  d44e0a:	mov    %r13,%rdx
  d44e0d:	ror    $0x2e,%rdx
  d44e11:	add    %rcx,%rdx
  d44e14:	movabs $0x9e3779b185ebca87,%rcx
  d44e1e:	ror    $0x21,%r12
  d44e22:	imul   %rcx,%r12
  d44e26:	imul   %r10,%rbx
  d44e2a:	imul   %r10,%r11
  d44e2e:	xor    %r12,%rdx
  d44e31:	movabs $0x85ebca77c2b2ae63,%r12
  d44e3b:	ror    $0x21,%rbx
  d44e3f:	imul   %rcx,%rdx
  d44e43:	ror    $0x21,%r11
  d44e47:	imul   %rcx,%rbx
  d44e4b:	imul   %rcx,%r11
  d44e4f:	add    %r12,%rdx
  d44e52:	xor    %rbx,%rdx
  d44e55:	imul   %rcx,%rdx
  d44e59:	imul   %r13,%r10
  d44e5d:	add    %r12,%rdx
  d44e60:	xor    %r11,%rdx
  d44e63:	ror    $0x21,%r10
  d44e67:	imul   %rcx,%rdx
  d44e6b:	imul   %rcx,%r10
  d44e6f:	add    %r12,%rdx
  d44e72:	xor    %r10,%rdx
  d44e75:	imul   %rcx,%rdx
  d44e79:	add    %r12,%rdx
  d44e7c:	lea    0x38(%rdi),%rbx
  d44e80:	add    %r9,%rdx
  d44e83:	cmp    %rbx,%r8
  d44e86:	jb     d44ef5 <XXH64_digest_endian+0x145>
  d44e88:	cmp    $0x1,%esi
  d44e8b:	je     d44fd0 <XXH64_digest_endian+0x220>
  d44e91:	mov    %rbx,%rcx
  d44e94:	movabs $0xc2b2ae3d27d4eb4f,%rdi
  d44e9e:	movabs $0x9e3779b185ebca87,%r10
  d44ea8:	movabs $0x85ebca77c2b2ae63,%r11
  d44eb2:	jmp    d44ebe <XXH64_digest_endian+0x10e>
  d44eb4:	nopl   0x0(%rax)
  d44eb8:	mov    %rcx,%rax
  d44ebb:	mov    %r9,%rcx
  d44ebe:	mov    (%rax),%rax
  d44ec1:	lea    0x8(%rcx),%r9
  d44ec5:	bswap  %rax
  d44ec8:	imul   %rdi,%rax
  d44ecc:	ror    $0x21,%rax
  d44ed0:	imul   %r10,%rax
  d44ed4:	xor    %rdx,%rax
  d44ed7:	ror    $0x25,%rax
  d44edb:	imul   %r10,%rax
  d44edf:	cmp    %r9,%r8
  d44ee2:	lea    (%rax,%r11,1),%rdx
  d44ee6:	jae    d44eb8 <XXH64_digest_endian+0x108>
  d44ee8:	mov    %r8,%rax
  d44eeb:	sub    %rbx,%rax
  d44eee:	and    $0xfffffffffffffff8,%rax
  d44ef2:	add    %rbx,%rax
  d44ef5:	lea    0x4(%rax),%rcx
  d44ef9:	cmp    %rcx,%r8
  d44efc:	jb     d44f3c <XXH64_digest_endian+0x18c>
  d44efe:	cmp    $0x1,%esi
  d44f01:	mov    (%rax),%eax
  d44f03:	je     d44f07 <XXH64_digest_endian+0x157>
  d44f05:	bswap  %eax
  d44f07:	mov    %eax,%eax
  d44f09:	movabs $0x9e3779b185ebca87,%rsi
  d44f13:	imul   %rsi,%rax
  d44f17:	xor    %rdx,%rax
  d44f1a:	movabs $0xc2b2ae3d27d4eb4f,%rdx
  d44f24:	ror    $0x29,%rax
  d44f28:	imul   %rdx,%rax
  d44f2c:	movabs $0x165667b19e3779f9,%rdx
  d44f36:	add    %rax,%rdx
  d44f39:	mov    %rcx,%rax
  d44f3c:	cmp    %rax,%r8
  d44f3f:	jbe    d44f73 <XXH64_digest_endian+0x1c3>
  d44f41:	movabs $0x27d4eb2f165667c5,%rdi
  d44f4b:	movabs $0x9e3779b185ebca87,%rsi
  d44f55:	nopl   (%rax)
  d44f58:	movzbl (%rax),%ecx
  d44f5b:	add    $0x1,%rax
  d44f5f:	imul   %rdi,%rcx
  d44f63:	xor    %rcx,%rdx
  d44f66:	ror    $0x35,%rdx
  d44f6a:	imul   %rsi,%rdx
  d44f6e:	cmp    %r8,%rax
  d44f71:	jne    d44f58 <XXH64_digest_endian+0x1a8>
  d44f73:	mov    %rdx,%rax
  d44f76:	shr    $0x21,%rax
  d44f7a:	xor    %rdx,%rax
  d44f7d:	movabs $0xc2b2ae3d27d4eb4f,%rdx
  d44f87:	imul   %rdx,%rax
  d44f8b:	pop    %rbx
  d44f8c:	pop    %r12
  d44f8e:	pop    %r13
  d44f90:	mov    %rax,%rdx
  d44f93:	shr    $0x1d,%rdx
  d44f97:	xor    %rax,%rdx
  d44f9a:	movabs $0x165667b19e3779f9,%rax
  d44fa4:	imul   %rax,%rdx
  d44fa8:	pop    %rbp
  d44fa9:	mov    %rdx,%rax
  d44fac:	shr    $0x20,%rax
  d44fb0:	xor    %rdx,%rax
  d44fb3:	retq   
  d44fb4:	nopl   0x0(%rax)
  d44fb8:	movabs $0x27d4eb2f165667c5,%rdx
  d44fc2:	add    0x8(%rdi),%rdx
  d44fc6:	jmpq   d44e7c <XXH64_digest_endian+0xcc>
  d44fcb:	nopl   0x0(%rax,%rax,1)
  d44fd0:	mov    %rbx,%r9
  d44fd3:	movabs $0xc2b2ae3d27d4eb4f,%r11
  d44fdd:	movabs $0x9e3779b185ebca87,%rdi
  d44fe7:	movabs $0x85ebca77c2b2ae63,%r10
  d44ff1:	jmp    d44ffe <XXH64_digest_endian+0x24e>
  d44ff3:	nopl   0x0(%rax,%rax,1)
  d44ff8:	mov    %r9,%rax
  d44ffb:	mov    %rcx,%r9
  d44ffe:	mov    %r11,%rcx
  d45001:	imul   (%rax),%rcx
  d45005:	mov    %rcx,%rax
  d45008:	lea    0x8(%r9),%rcx
  d4500c:	ror    $0x21,%rax
  d45010:	imul   %rdi,%rax
  d45014:	xor    %rdx,%rax
  d45017:	ror    $0x25,%rax
  d4501b:	imul   %rdi,%rax
  d4501f:	cmp    %rcx,%r8
  d45022:	lea    (%rax,%r10,1),%rdx
  d45026:	jae    d44ff8 <XXH64_digest_endian+0x248>
  d45028:	jmpq   d44ee8 <XXH64_digest_endian+0x138>
  d4502d:	nopl   (%rax)
