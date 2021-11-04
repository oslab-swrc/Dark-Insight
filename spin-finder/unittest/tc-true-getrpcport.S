// TC_OUT getrpcport,0x12dad8,0x12db21,-0x68(%rbp),-0x6c(%rbp)
000000000012da90 <getrpcport>:
  12da90:	push   %rbp
  12da91:	mov    %rsp,%rbp
  12da94:	push   %r15
  12da96:	push   %r14
  12da98:	push   %r13
  12da9a:	push   %r12
  12da9c:	mov    %rdi,%r14
  12da9f:	push   %rbx
  12daa0:	mov    $0x400,%r15d
  12daa6:	lea    -0x6c(%rbp),%r13
  12daaa:	lea    -0x68(%rbp),%r12
  12daae:	lea    -0x50(%rbp),%rbx
  12dab2:	sub    $0x478,%rsp
  12dab9:	mov    %rdx,-0x80(%rbp)
  12dabd:	mov    %rsi,-0x78(%rbp)
  12dac1:	lea    0xf(%rsp),%rdx
  12dac6:	mov    %ecx,-0x84(%rbp)
  12dacc:	and    $0xfffffffffffffff0,%rdx
  12dad0:	jmp    12dafc <getrpcport+0x6c>
  12dad2:	nopw   0x0(%rax,%rax,1)
  12dad8:	mov    0x292389(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
  12dadf:	cmpl   $0x22,%fs:(%rax)
  12dae3:	jne    12db23 <getrpcport+0x93>
  12dae5:	add    %r15,%r15
  12dae8:	lea    0x1e(%r15),%rax
  12daec:	and    $0xfffffffffffffff0,%rax
  12daf0:	sub    %rax,%rsp
  12daf3:	lea    0xf(%rsp),%rdx
  12daf8:	and    $0xfffffffffffffff0,%rdx
  12dafc:	mov    %r13,%r9
  12daff:	mov    %r12,%r8
  12db02:	mov    %r15,%rcx
  12db05:	mov    %rbx,%rsi
  12db08:	mov    %r14,%rdi
  12db0b:	callq  11b680 <gethostbyname_r@@GLIBC_2.2.5>
  12db10:	test   %eax,%eax
  12db12:	jne    12db1d <getrpcport+0x8d>
  12db14:	mov    -0x68(%rbp),%rax
  12db18:	test   %rax,%rax
  12db1b:	jne    12db38 <getrpcport+0xa8>
  12db1d:	cmpl   $0xffffffff,-0x6c(%rbp)
  12db21:	je     12dad8 <getrpcport+0x48>
  12db23:	lea    -0x28(%rbp),%rsp
  12db27:	xor    %eax,%eax
  12db29:	pop    %rbx
  12db2a:	pop    %r12
  12db2c:	pop    %r13
  12db2e:	pop    %r14
  12db30:	pop    %r15
  12db32:	pop    %rbp
  12db33:	retq   
  12db34:	nopl   0x0(%rax)
  12db38:	movslq 0x14(%rax),%rdx
  12db3c:	mov    0x18(%rax),%rax
  12db40:	lea    -0x60(%rbp),%rbx
  12db44:	lea    0x4(%rbx),%rdi
  12db48:	mov    (%rax),%rsi
  12db4b:	callq  909a0 <memcpy@GLIBC_2.2.5>
  12db50:	xor    %edx,%edx
  12db52:	mov    -0x84(%rbp),%ecx
  12db58:	mov    -0x78(%rbp),%rsi
  12db5c:	mov    %dx,-0x5e(%rbp)
  12db60:	mov    -0x80(%rbp),%rdx
  12db64:	mov    $0x2,%eax
  12db69:	mov    %rbx,%rdi
  12db6c:	mov    %ax,-0x60(%rbp)
  12db70:	callq  139660 <pmap_getport>
  12db75:	lea    -0x28(%rbp),%rsp
  12db79:	movzwl %ax,%eax
  12db7c:	pop    %rbx
  12db7d:	pop    %r12
  12db7f:	pop    %r13
  12db81:	pop    %r14
  12db83:	pop    %r15
  12db85:	pop    %rbp
  12db86:	retq   
  12db87:	nopw   0x0(%rax,%rax,1)

