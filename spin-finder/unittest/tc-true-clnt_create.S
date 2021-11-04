// TC_OUT clnt_create,0x135e48,0x135e97,-0xe0(%rbp),-0xe4(%rbp)
// TC_OUT clnt_create,0x135f28,0x135f6f,-0xd8(%rbp)
0000000000135d60 <clnt_create>:
  135d60:	push   %rbp
  135d61:	mov    %rcx,%rax
  135d64:	mov    %rsp,%rbp
  135d67:	push   %r15
  135d69:	push   %r14
  135d6b:	push   %r13
  135d6d:	push   %r12
  135d6f:	mov    %rsi,%r15
  135d72:	push   %rbx
  135d73:	mov    %rdi,%rbx
  135d76:	lea    0x56cd2(%rip),%rdi        # 18ca4f <OPSYS>
  135d7d:	mov    %rdx,%r14
  135d80:	sub    $0xe8,%rsp
  135d87:	mov    %rsi,-0x100(%rbp)
  135d8e:	mov    %rcx,-0xf8(%rbp)
  135d95:	mov    %rdx,-0x108(%rbp)
  135d9c:	mov    $0x5,%ecx
  135da1:	mov    %rax,%rsi
  135da4:	repz cmpsb %es:(%rdi),%ds:(%rsi)
  135da6:	jne    135e18 <clnt_create+0xb8>
  135da8:	lea    -0xa0(%rbp),%r12
  135daf:	xor    %eax,%eax
  135db1:	mov    $0xd,%ecx
  135db6:	xor    %esi,%esi
  135db8:	mov    %r12,%rdi
  135dbb:	rep stos %rax,%es:(%rdi)
  135dbe:	mov    %si,0x4(%rdi)
  135dc2:	movl   $0x0,(%rdi)
  135dc8:	mov    $0x1,%edi
  135dcd:	mov    %di,-0xa0(%rbp)
  135dd4:	lea    0x2(%r12),%rdi
  135dd9:	mov    %rbx,%rsi
  135ddc:	callq  8caa0 <__GI_strcpy>
  135de1:	lea    -0xe8(%rbp),%rcx
  135de8:	xor    %r9d,%r9d
  135deb:	xor    %r8d,%r8d
  135dee:	mov    %r14,%rdx
  135df1:	mov    %r15,%rsi
  135df4:	mov    %r12,%rdi
  135df7:	movl   $0xffffffff,-0xe8(%rbp)
  135e01:	callq  134140 <clntunix_create>
  135e06:	lea    -0x28(%rbp),%rsp
  135e0a:	pop    %rbx
  135e0b:	pop    %r12
  135e0d:	pop    %r13
  135e0f:	pop    %r14
  135e11:	pop    %r15
  135e13:	pop    %rbp
  135e14:	retq   
  135e15:	nopl   (%rax)
  135e18:	sub    $0x410,%rsp
  135e1f:	mov    $0x400,%r15d
  135e25:	lea    -0xa0(%rbp),%r14
  135e2c:	lea    0xf(%rsp),%rdx
  135e31:	lea    -0xe4(%rbp),%r13
  135e38:	lea    -0xe0(%rbp),%r12
  135e3f:	and    $0xfffffffffffffff0,%rdx
  135e43:	jmp    135e6c <clnt_create+0x10c>
  135e45:	nopl   (%rax)
  135e48:	mov    0x28a019(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
  135e4f:	cmpl   $0x22,%fs:(%rax)
  135e53:	jne    135e99 <clnt_create+0x139>
  135e55:	add    %r15,%r15
  135e58:	lea    0x1e(%r15),%rax
  135e5c:	and    $0xfffffffffffffff0,%rax
  135e60:	sub    %rax,%rsp
  135e63:	lea    0xf(%rsp),%rdx
  135e68:	and    $0xfffffffffffffff0,%rdx
  135e6c:	mov    %r13,%r9
  135e6f:	mov    %r12,%r8
  135e72:	mov    %r15,%rcx
  135e75:	mov    %r14,%rsi
  135e78:	mov    %rbx,%rdi
  135e7b:	callq  11b680 <gethostbyname_r@@GLIBC_2.2.5>
  135e80:	test   %eax,%eax
  135e82:	jne    135e90 <clnt_create+0x130>
  135e84:	mov    -0xe0(%rbp),%rax
  135e8b:	test   %rax,%rax
  135e8e:	jne    135eb8 <clnt_create+0x158>
  135e90:	cmpl   $0xffffffff,-0xe4(%rbp)
  135e97:	je     135e48 <clnt_create+0xe8>
  135e99:	callq  139980 <__rpc_thread_createerr>
  135e9e:	movl   $0xd,(%rax)
  135ea4:	lea    -0x28(%rbp),%rsp
  135ea8:	xor    %eax,%eax
  135eaa:	pop    %rbx
  135eab:	pop    %r12
  135ead:	pop    %r13
  135eaf:	pop    %r14
  135eb1:	pop    %r15
  135eb3:	pop    %rbp
  135eb4:	retq   
  135eb5:	nopl   (%rax)
  135eb8:	cmpl   $0x2,0x10(%rax)
  135ebc:	jne    135f8a <clnt_create+0x22a>
  135ec2:	mov    $0x2,%edx
  135ec7:	lea    -0xd0(%rbp),%r13
  135ece:	movq   $0x0,-0xc8(%rbp)
  135ed9:	mov    %dx,-0xd0(%rbp)
  135ee0:	movslq 0x14(%rax),%rdx
  135ee4:	xor    %ecx,%ecx
  135ee6:	mov    0x18(%rax),%rax
  135eea:	lea    0x4(%r13),%rdi
  135eee:	mov    %cx,-0xce(%rbp)
  135ef5:	mov    $0x400,%r14d
  135efb:	lea    -0xd8(%rbp),%r12
  135f02:	lea    -0xc0(%rbp),%rbx
  135f09:	mov    (%rax),%rsi
  135f0c:	callq  909a0 <memcpy@GLIBC_2.2.5>
  135f11:	sub    $0x410,%rsp
  135f18:	lea    0xf(%rsp),%rdx
  135f1d:	and    $0xfffffffffffffff0,%rdx
  135f21:	jmp    135f3f <clnt_create+0x1df>
  135f23:	nopl   0x0(%rax,%rax,1)
  135f28:	add    %r14,%r14
  135f2b:	lea    0x1e(%r14),%rax
  135f2f:	and    $0xfffffffffffffff0,%rax
  135f33:	sub    %rax,%rsp
  135f36:	lea    0xf(%rsp),%rdx
  135f3b:	and    $0xfffffffffffffff0,%rdx
  135f3f:	mov    -0xf8(%rbp),%rdi
  135f46:	mov    %r12,%r8
  135f49:	mov    %r14,%rcx
  135f4c:	mov    %rbx,%rsi
  135f4f:	callq  11d5f0 <getprotobyname_r@@GLIBC_2.2.5>
  135f54:	test   %eax,%eax
  135f56:	jne    135f64 <clnt_create+0x204>
  135f58:	mov    -0xd8(%rbp),%rax
  135f5f:	test   %rax,%rax
  135f62:	jne    135fa3 <clnt_create+0x243>
  135f64:	mov    0x289efd(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
  135f6b:	cmpl   $0x22,%fs:(%rax)
  135f6f:	je     135f28 <clnt_create+0x1c8>
  135f71:	callq  139980 <__rpc_thread_createerr>
  135f76:	movl   $0x11,(%rax)
  135f7c:	movl   $0x60,0x10(%rax)
  135f83:	xor    %eax,%eax
  135f85:	jmpq   135e06 <clnt_create+0xa6>
  135f8a:	callq  139980 <__rpc_thread_createerr>
  135f8f:	movl   $0xc,(%rax)
  135f95:	movl   $0x61,0x10(%rax)
  135f9c:	xor    %eax,%eax
  135f9e:	jmpq   135e06 <clnt_create+0xa6>
  135fa3:	mov    0x10(%rax),%eax
  135fa6:	movl   $0xffffffff,-0xe8(%rbp)
  135fb0:	cmp    $0x6,%eax
  135fb3:	je     135fe4 <clnt_create+0x284>
  135fb5:	cmp    $0x11,%eax
  135fb8:	jne    13600c <clnt_create+0x2ac>
  135fba:	mov    -0x108(%rbp),%rdx
  135fc1:	mov    -0x100(%rbp),%rsi
  135fc8:	lea    -0xe8(%rbp),%r9
  135fcf:	mov    $0x5,%ecx
  135fd4:	xor    %r8d,%r8d
  135fd7:	mov    %r13,%rdi
  135fda:	callq  137db0 <clntudp_create>
  135fdf:	jmpq   135e06 <clnt_create+0xa6>
  135fe4:	mov    -0x108(%rbp),%rdx
  135feb:	mov    -0x100(%rbp),%rsi
  135ff2:	lea    -0xe8(%rbp),%rcx
  135ff9:	xor    %r9d,%r9d
  135ffc:	xor    %r8d,%r8d
  135fff:	mov    %r13,%rdi
  136002:	callq  136c30 <clnttcp_create>
  136007:	jmpq   135e06 <clnt_create+0xa6>
  13600c:	callq  139980 <__rpc_thread_createerr>
  136011:	movl   $0xc,(%rax)
  136017:	movl   $0x60,0x10(%rax)
  13601e:	xor    %eax,%eax
  136020:	jmpq   135e06 <clnt_create+0xa6>
  136025:	nopw   %cs:0x0(%rax,%rax,1)
  13602f:	nop
