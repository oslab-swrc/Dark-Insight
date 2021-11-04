// TC_OUT callrpc,0x12d850,0x12d899,-0x68(%rbp),-0x6c(%rbp)
000000000012d780 <callrpc>:
  12d780:	push   %rbp
  12d781:	mov    %rsp,%rbp
  12d784:	push   %r15
  12d786:	push   %r14
  12d788:	push   %r13
  12d78a:	push   %r12
  12d78c:	push   %rbx
  12d78d:	mov    %rdi,%rbx
  12d790:	sub    $0x78,%rsp
  12d794:	mov    %rsi,-0x80(%rbp)
  12d798:	mov    %rdx,-0x88(%rbp)
  12d79f:	mov    %rcx,-0x90(%rbp)
  12d7a6:	mov    %r8,-0x98(%rbp)
  12d7ad:	mov    %r9,-0xa0(%rbp)
  12d7b4:	callq  1398b0 <__rpc_thread_variables>
  12d7b9:	mov    %rax,%r12
  12d7bc:	mov    0xc0(%rax),%rax
  12d7c3:	test   %rax,%rax
  12d7c6:	mov    %rax,-0x78(%rbp)
  12d7ca:	je     12d9c2 <callrpc+0x242>
  12d7d0:	cmpq   $0x0,0x28(%rax)
  12d7d5:	je     12d9e7 <callrpc+0x267>
  12d7db:	cmpq   $0x0,0x20(%rax)
  12d7e0:	je     12d7f0 <callrpc+0x70>
  12d7e2:	mov    -0x80(%rbp),%rcx
  12d7e6:	cmp    %rcx,0x10(%rax)
  12d7ea:	je     12d990 <callrpc+0x210>
  12d7f0:	mov    -0x78(%rbp),%r14
  12d7f4:	mov    0x8(%r14),%edi
  12d7f8:	movq   $0x0,0x20(%r14)
  12d800:	cmp    $0xffffffff,%edi
  12d803:	je     12d816 <callrpc+0x96>
  12d805:	callq  f8240 <__close>
  12d80a:	movl   $0xffffffff,0x8(%r14)
  12d812:	mov    -0x78(%rbp),%r14
  12d816:	mov    (%r14),%rdi
  12d819:	test   %rdi,%rdi
  12d81c:	je     12d82c <callrpc+0xac>
  12d81e:	mov    0x8(%rdi),%rax
  12d822:	callq  *0x20(%rax)
  12d825:	movq   $0x0,(%r14)
  12d82c:	sub    $0x410,%rsp
  12d833:	mov    $0x400,%r15d
  12d839:	lea    -0x6c(%rbp),%r14
  12d83d:	lea    0xf(%rsp),%rdx
  12d842:	lea    -0x68(%rbp),%r13
  12d846:	lea    -0x50(%rbp),%r12
  12d84a:	and    $0xfffffffffffffff0,%rdx
  12d84e:	jmp    12d874 <callrpc+0xf4>
  12d850:	mov    0x292611(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
  12d857:	cmpl   $0x22,%fs:(%rax)
  12d85b:	jne    12d89b <callrpc+0x11b>
  12d85d:	add    %r15,%r15
  12d860:	lea    0x1e(%r15),%rax
  12d864:	and    $0xfffffffffffffff0,%rax
  12d868:	sub    %rax,%rsp
  12d86b:	lea    0xf(%rsp),%rdx
  12d870:	and    $0xfffffffffffffff0,%rdx
  12d874:	mov    %r14,%r9
  12d877:	mov    %r13,%r8
  12d87a:	mov    %r15,%rcx
  12d87d:	mov    %r12,%rsi
  12d880:	mov    %rbx,%rdi
  12d883:	callq  11b680 <gethostbyname_r@@GLIBC_2.2.5>
  12d888:	test   %eax,%eax
  12d88a:	jne    12d895 <callrpc+0x115>
  12d88c:	mov    -0x68(%rbp),%rax
  12d890:	test   %rax,%rax
  12d893:	jne    12d8b0 <callrpc+0x130>
  12d895:	cmpl   $0xffffffff,-0x6c(%rbp)
  12d899:	je     12d850 <callrpc+0xd0>
  12d89b:	mov    $0xd,%eax
  12d8a0:	lea    -0x28(%rbp),%rsp
  12d8a4:	pop    %rbx
  12d8a5:	pop    %r12
  12d8a7:	pop    %r13
  12d8a9:	pop    %r14
  12d8ab:	pop    %r15
  12d8ad:	pop    %rbp
  12d8ae:	retq   
  12d8af:	nop
  12d8b0:	movslq 0x14(%rax),%rdx
  12d8b4:	mov    0x18(%rax),%rax
  12d8b8:	lea    -0x60(%rbp),%r12
  12d8bc:	lea    0x4(%r12),%rdi
  12d8c1:	mov    (%rax),%rsi
  12d8c4:	callq  909a0 <memcpy@GLIBC_2.2.5>
  12d8c9:	mov    -0x78(%rbp),%r14
  12d8cd:	mov    $0x2,%esi
  12d8d2:	mov    -0x88(%rbp),%rdx
  12d8d9:	mov    %si,-0x60(%rbp)
  12d8dd:	mov    -0x80(%rbp),%rsi
  12d8e1:	xor    %edi,%edi
  12d8e3:	mov    %di,-0x5e(%rbp)
  12d8e7:	xor    %r8d,%r8d
  12d8ea:	mov    $0x5,%ecx
  12d8ef:	lea    0x8(%r14),%r9
  12d8f3:	mov    %r12,%rdi
  12d8f6:	callq  137db0 <clntudp_create>
  12d8fb:	test   %rax,%rax
  12d8fe:	mov    %rax,(%r14)
  12d901:	je     12d9b6 <callrpc+0x236>
  12d907:	mov    -0x78(%rbp),%r14
  12d90b:	mov    -0x80(%rbp),%rsi
  12d90f:	mov    $0xff,%edx
  12d914:	mov    -0x88(%rbp),%rcx
  12d91b:	mov    0x28(%r14),%rdi
  12d91f:	mov    %rsi,0x10(%r14)
  12d923:	mov    %rbx,%rsi
  12d926:	movq   $0x1,0x20(%r14)
  12d92e:	mov    %rcx,0x18(%r14)
  12d932:	callq  a06a0 <__GI_strncpy>
  12d937:	mov    0x28(%r14),%rax
  12d93b:	movb   $0x0,0xff(%rax)
  12d942:	mov    -0x78(%rbp),%rbx
  12d946:	mov    -0xa0(%rbp),%rcx
  12d94d:	mov    -0x98(%rbp),%rdx
  12d954:	mov    0x18(%rbp),%r9
  12d958:	mov    0x10(%rbp),%r8
  12d95c:	mov    -0x90(%rbp),%rsi
  12d963:	mov    (%rbx),%rdi
  12d966:	mov    0x8(%rdi),%rax
  12d96a:	pushq  $0x0
  12d96c:	pushq  $0x19
  12d96e:	callq  *(%rax)
  12d970:	test   %eax,%eax
  12d972:	pop    %rdx
  12d973:	pop    %rcx
  12d974:	je     12d8a0 <callrpc+0x120>
  12d97a:	movq   $0x0,0x20(%rbx)
  12d982:	jmpq   12d8a0 <callrpc+0x120>
  12d987:	nopw   0x0(%rax,%rax,1)
  12d990:	mov    -0x88(%rbp),%rcx
  12d997:	cmp    %rcx,0x18(%rax)
  12d99b:	jne    12d7f0 <callrpc+0x70>
  12d9a1:	mov    0x28(%rax),%rdi
  12d9a5:	mov    %rbx,%rsi
  12d9a8:	callq  8b610 <__GI_strcmp>
  12d9ad:	test   %eax,%eax
  12d9af:	je     12d942 <callrpc+0x1c2>
  12d9b1:	jmpq   12d7f0 <callrpc+0x70>
  12d9b6:	callq  139980 <__rpc_thread_createerr>
  12d9bb:	mov    (%rax),%eax
  12d9bd:	jmpq   12d8a0 <callrpc+0x120>
  12d9c2:	mov    $0x30,%esi
  12d9c7:	mov    $0x1,%edi
  12d9cc:	callq  1f9b8 <*ABS*+0x91210@plt+0x38>
  12d9d1:	test   %rax,%rax
  12d9d4:	mov    %rax,-0x78(%rbp)
  12d9d8:	je     12da0b <callrpc+0x28b>
  12d9da:	mov    %rax,0xc0(%r12)
  12d9e2:	jmpq   12d7d0 <callrpc+0x50>
  12d9e7:	mov    $0x100,%edi
  12d9ec:	callq  1f998 <*ABS*+0x91210@plt+0x18>
  12d9f1:	mov    -0x78(%rbp),%rsi
  12d9f5:	mov    %rax,0x28(%rsi)
  12d9f9:	movb   $0x0,(%rax)
  12d9fc:	mov    %rsi,%rax
  12d9ff:	movl   $0xffffffff,0x8(%rsi)
  12da06:	jmpq   12d7db <callrpc+0x5b>
  12da0b:	xor    %eax,%eax
  12da0d:	jmpq   12d8a0 <callrpc+0x120>
  12da12:	nopl   0x0(%rax)
  12da16:	nopw   %cs:0x0(%rax,%rax,1)
