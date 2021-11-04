// TC_OUT thread,0x400bb8,0x400bda,0x0(%rdi)
// TC_OUT thread,0x400d48,0x400d6a,0x0(%rdi)
0000000000400b30 <thread>:
  400b30:	push   %rbx
  400b31:	add    $0xffffffffffffff80,%rsp
  400b35:	mov    0x2015a5(%rip),%esi        # 6020e0 <a>
  400b3b:	lock xadd %esi,0x2015a1(%rip)        # 6020e4 <a+0x4>
  400b43:	xor    %eax,%eax
  400b45:	mov    $0x10,%ecx
  400b4a:	mov    %rsp,%rdi
  400b4d:	rep stos %rax,%es:(%rdi)
  400b50:	and    $0x3,%esi
  400b53:	mov    $0x1,%eax
  400b58:	mov    $0xba,%edi
  400b5d:	mov    %esi,%ecx
  400b5f:	shl    %cl,%rax
  400b62:	mov    %rax,(%rsp)
  400b66:	xor    %eax,%eax
  400b68:	callq  400760 <syscall@plt>
  400b6d:	mov    %rsp,%rdx
  400b70:	mov    $0x80,%esi
  400b75:	mov    %eax,%edi
  400b77:	callq  400750 <sched_setaffinity@plt>
  400b7c:	test   %eax,%eax
  400b7e:	jne    400db8 <thread+0x288>
  400b84:	lea    0x201535(%rip),%rdi        # 6020c0 <lock>
  400b8b:	mov    $0x989680,%r8d
  400b91:	mov    $0x200,%edx
  400b96:	nopw   %cs:0x0(%rax,%rax,1)
  400ba0:	lock decl 0x201519(%rip)        # 6020c0 <lock>
  400ba7:	sete   (%rsp)
  400bab:	cmpb   $0x0,(%rsp)
  400baf:	jne    400bdc <thread+0xac>
  400bb1:	nopl   0x0(%rax)
  400bb8:	mov    (%rdi),%eax
  400bba:	cmp    $0x1,%eax
  400bbd:	je     400ba0 <thread+0x70>
  400bbf:	xor    %eax,%eax
  400bc1:	test   %edx,%edx
  400bc3:	je     400bcf <thread+0x9f>
  400bc5:	nopl   (%rax)
  400bc8:	add    $0x1,%eax
  400bcb:	cmp    %edx,%eax
  400bcd:	jne    400bc8 <thread+0x98>
  400bcf:	cmp    $0xffffe,%edx
  400bd5:	setbe  %cl
  400bd8:	shl    %cl,%edx
  400bda:	jmp    400bb8 <thread+0x88>
  400bdc:	mov    (%rdi),%eax
  400bde:	cmp    $0x1,%eax
  400be1:	je     400daa <thread+0x27a>
  400be7:	mov    0x2014eb(%rip),%eax        # 6020d8 <locked>
  400bed:	add    $0x1,%eax
  400bf0:	mov    %eax,0x2014e2(%rip)        # 6020d8 <locked>
  400bf6:	mov    0x2014dc(%rip),%eax        # 6020d8 <locked>
  400bfc:	add    $0x1,%eax
  400bff:	mov    %eax,0x2014d3(%rip)        # 6020d8 <locked>
  400c05:	mov    0x2014cd(%rip),%eax        # 6020d8 <locked>
  400c0b:	add    $0x1,%eax
  400c0e:	mov    %eax,0x2014c4(%rip)        # 6020d8 <locked>
  400c14:	mov    0x2014be(%rip),%eax        # 6020d8 <locked>
  400c1a:	add    $0x1,%eax
  400c1d:	mov    %eax,0x2014b5(%rip)        # 6020d8 <locked>
  400c23:	mov    0x2014af(%rip),%eax        # 6020d8 <locked>
  400c29:	add    $0x1,%eax
  400c2c:	mov    %eax,0x2014a6(%rip)        # 6020d8 <locked>
  400c32:	mov    0x2014a0(%rip),%eax        # 6020d8 <locked>
  400c38:	add    $0x1,%eax
  400c3b:	mov    %eax,0x201497(%rip)        # 6020d8 <locked>
  400c41:	mov    0x201491(%rip),%eax        # 6020d8 <locked>
  400c47:	add    $0x1,%eax
  400c4a:	mov    %eax,0x201488(%rip)        # 6020d8 <locked>
  400c50:	mov    0x201482(%rip),%eax        # 6020d8 <locked>
  400c56:	add    $0x1,%eax
  400c59:	mov    %eax,0x201479(%rip)        # 6020d8 <locked>
  400c5f:	mov    0x201473(%rip),%eax        # 6020d8 <locked>
  400c65:	add    $0x1,%eax
  400c68:	mov    %eax,0x20146a(%rip)        # 6020d8 <locked>
  400c6e:	mov    0x201464(%rip),%eax        # 6020d8 <locked>
  400c74:	add    $0x1,%eax
  400c77:	mov    %eax,0x20145b(%rip)        # 6020d8 <locked>
  400c7d:	mov    0x201455(%rip),%esi        # 6020d8 <locked>
  400c83:	cmp    $0xa,%esi
  400c86:	jne    400d8e <thread+0x25e>
  400c8c:	mov    0x201446(%rip),%eax        # 6020d8 <locked>
  400c92:	sub    $0x1,%eax
  400c95:	mov    %eax,0x20143d(%rip)        # 6020d8 <locked>
  400c9b:	mov    0x201437(%rip),%eax        # 6020d8 <locked>
  400ca1:	sub    $0x1,%eax
  400ca4:	mov    %eax,0x20142e(%rip)        # 6020d8 <locked>
  400caa:	mov    0x201428(%rip),%eax        # 6020d8 <locked>
  400cb0:	sub    $0x1,%eax
  400cb3:	mov    %eax,0x20141f(%rip)        # 6020d8 <locked>
  400cb9:	mov    0x201419(%rip),%eax        # 6020d8 <locked>
  400cbf:	sub    $0x1,%eax
  400cc2:	mov    %eax,0x201410(%rip)        # 6020d8 <locked>
  400cc8:	mov    0x20140a(%rip),%eax        # 6020d8 <locked>
  400cce:	sub    $0x1,%eax
  400cd1:	mov    %eax,0x201401(%rip)        # 6020d8 <locked>
  400cd7:	mov    0x2013fb(%rip),%eax        # 6020d8 <locked>
  400cdd:	sub    $0x1,%eax
  400ce0:	mov    %eax,0x2013f2(%rip)        # 6020d8 <locked>
  400ce6:	mov    0x2013ec(%rip),%eax        # 6020d8 <locked>
  400cec:	sub    $0x1,%eax
  400cef:	mov    %eax,0x2013e3(%rip)        # 6020d8 <locked>
  400cf5:	mov    0x2013dd(%rip),%eax        # 6020d8 <locked>
  400cfb:	sub    $0x1,%eax
  400cfe:	mov    %eax,0x2013d4(%rip)        # 6020d8 <locked>
  400d04:	mov    0x2013ce(%rip),%eax        # 6020d8 <locked>
  400d0a:	sub    $0x1,%eax
  400d0d:	mov    %eax,0x2013c5(%rip)        # 6020d8 <locked>
  400d13:	mov    0x2013bf(%rip),%eax        # 6020d8 <locked>
  400d19:	sub    $0x1,%eax
  400d1c:	mov    %eax,0x2013b6(%rip)        # 6020d8 <locked>
  400d22:	movl   $0x1,(%rdi)
  400d28:	mov    $0x200,%edx
  400d2d:	nopl   (%rax)
  400d30:	lock decl 0x201389(%rip)        # 6020c0 <lock>
  400d37:	sete   (%rsp)
  400d3b:	cmpb   $0x0,(%rsp)
  400d3f:	jne    400d6c <thread+0x23c>
  400d41:	nopl   0x0(%rax)
  400d48:	mov    (%rdi),%eax
  400d4a:	cmp    $0x1,%eax
  400d4d:	je     400d30 <thread+0x200>
  400d4f:	xor    %eax,%eax
  400d51:	test   %edx,%edx
  400d53:	je     400d5f <thread+0x22f>
  400d55:	nopl   (%rax)
  400d58:	add    $0x1,%eax
  400d5b:	cmp    %edx,%eax
  400d5d:	jne    400d58 <thread+0x228>
  400d5f:	cmp    $0xffffe,%edx
  400d65:	setbe  %cl
  400d68:	shl    %cl,%edx
  400d6a:	jmp    400d48 <thread+0x218>
  400d6c:	mov    0x201366(%rip),%esi        # 6020d8 <locked>
  400d72:	test   %esi,%esi
  400d74:	jne    400d9c <thread+0x26c>
  400d76:	movl   $0x1,(%rdi)
  400d7c:	sub    $0x1,%r8d
  400d80:	jne    400b91 <thread+0x61>
  400d86:	sub    $0xffffffffffffff80,%rsp
  400d8a:	xor    %eax,%eax
  400d8c:	pop    %rbx
  400d8d:	retq   
  400d8e:	lea    0xeb(%rip),%rdi        # 400e80 <__dso_handle+0x28>
  400d95:	xor    %eax,%eax
  400d97:	callq  400a80 <ck_error>
  400d9c:	lea    0x105(%rip),%rdi        # 400ea8 <__dso_handle+0x50>
  400da3:	xor    %eax,%eax
  400da5:	callq  400a80 <ck_error>
  400daa:	lea    0x247(%rip),%rdi        # 400ff8 <__dso_handle+0x1a0>
  400db1:	xor    %eax,%eax
  400db3:	callq  400a80 <ck_error>
  400db8:	lea    0xa1(%rip),%rdi        # 400e60 <__dso_handle+0x8>
  400dbf:	callq  400790 <perror@plt>
  400dc4:	mov    $0x1,%edi
  400dc9:	callq  4007c0 <exit@plt>
  400dce:	xchg   %ax,%ax
