// TC_OUT thread,0x400bb0,0x400bdd,0x0(0x6020c0)
// TC_OUT thread,0x400d40,0x400d6d,0x0(0x6020c0)
0000000000400b30 <thread>:
  400b30:	push   %rbx
  400b31:	add    $0xffffffffffffff80,%rsp
  400b35:	mov    0x20159d(%rip),%esi        # 6020d8 <a>
  400b3b:	lock xadd %esi,0x201599(%rip)        # 6020dc <a+0x4>
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
  400b7e:	jne    400dba <thread+0x28a>
  400b84:	lea    0x201535(%rip),%r8        # 6020c0 <lock>
  400b8b:	mov    $0xf4240,%r9d
  400b91:	mov    $0x1,%edi
  400b96:	mov    %edi,%eax
  400b98:	xchg   %eax,0x201522(%rip)        # 6020c0 <lock>
  400b9e:	cmp    $0x1,%eax
  400ba1:	mov    $0x200,%edx
  400ba6:	jne    400bdf <thread+0xaf>
  400ba8:	nopl   0x0(%rax,%rax,1)
  400bb0:	xor    %eax,%eax
  400bb2:	test   %edx,%edx
  400bb4:	je     400bc7 <thread+0x97>
  400bb6:	nopw   %cs:0x0(%rax,%rax,1)
  400bc0:	add    $0x1,%eax
  400bc3:	cmp    %edx,%eax
  400bc5:	jne    400bc0 <thread+0x90>
  400bc7:	cmp    $0xffffe,%edx
  400bcd:	mov    %edi,%eax
  400bcf:	setbe  %cl
  400bd2:	shl    %cl,%edx
  400bd4:	xchg   %eax,0x2014e6(%rip)        # 6020c0 <lock>
  400bda:	cmp    $0x1,%eax
  400bdd:	je     400bb0 <thread+0x80>
  400bdf:	mov    (%r8),%eax
  400be2:	test   %eax,%eax
  400be4:	je     400dae <thread+0x27e>
  400bea:	mov    0x2014e0(%rip),%eax        # 6020d0 <locked>
  400bf0:	add    $0x1,%eax
  400bf3:	mov    %eax,0x2014d7(%rip)        # 6020d0 <locked>
  400bf9:	mov    0x2014d1(%rip),%eax        # 6020d0 <locked>
  400bff:	add    $0x1,%eax
  400c02:	mov    %eax,0x2014c8(%rip)        # 6020d0 <locked>
  400c08:	mov    0x2014c2(%rip),%eax        # 6020d0 <locked>
  400c0e:	add    $0x1,%eax
  400c11:	mov    %eax,0x2014b9(%rip)        # 6020d0 <locked>
  400c17:	mov    0x2014b3(%rip),%eax        # 6020d0 <locked>
  400c1d:	add    $0x1,%eax
  400c20:	mov    %eax,0x2014aa(%rip)        # 6020d0 <locked>
  400c26:	mov    0x2014a4(%rip),%eax        # 6020d0 <locked>
  400c2c:	add    $0x1,%eax
  400c2f:	mov    %eax,0x20149b(%rip)        # 6020d0 <locked>
  400c35:	mov    0x201495(%rip),%eax        # 6020d0 <locked>
  400c3b:	add    $0x1,%eax
  400c3e:	mov    %eax,0x20148c(%rip)        # 6020d0 <locked>
  400c44:	mov    0x201486(%rip),%eax        # 6020d0 <locked>
  400c4a:	add    $0x1,%eax
  400c4d:	mov    %eax,0x20147d(%rip)        # 6020d0 <locked>
  400c53:	mov    0x201477(%rip),%eax        # 6020d0 <locked>
  400c59:	add    $0x1,%eax
  400c5c:	mov    %eax,0x20146e(%rip)        # 6020d0 <locked>
  400c62:	mov    0x201468(%rip),%eax        # 6020d0 <locked>
  400c68:	add    $0x1,%eax
  400c6b:	mov    %eax,0x20145f(%rip)        # 6020d0 <locked>
  400c71:	mov    0x201459(%rip),%eax        # 6020d0 <locked>
  400c77:	add    $0x1,%eax
  400c7a:	mov    %eax,0x201450(%rip)        # 6020d0 <locked>
  400c80:	mov    0x20144a(%rip),%esi        # 6020d0 <locked>
  400c86:	cmp    $0xa,%esi
  400c89:	jne    400da0 <thread+0x270>
  400c8f:	mov    0x20143b(%rip),%eax        # 6020d0 <locked>
  400c95:	sub    $0x1,%eax
  400c98:	mov    %eax,0x201432(%rip)        # 6020d0 <locked>
  400c9e:	mov    0x20142c(%rip),%eax        # 6020d0 <locked>
  400ca4:	sub    $0x1,%eax
  400ca7:	mov    %eax,0x201423(%rip)        # 6020d0 <locked>
  400cad:	mov    0x20141d(%rip),%eax        # 6020d0 <locked>
  400cb3:	sub    $0x1,%eax
  400cb6:	mov    %eax,0x201414(%rip)        # 6020d0 <locked>
  400cbc:	mov    0x20140e(%rip),%eax        # 6020d0 <locked>
  400cc2:	sub    $0x1,%eax
  400cc5:	mov    %eax,0x201405(%rip)        # 6020d0 <locked>
  400ccb:	mov    0x2013ff(%rip),%eax        # 6020d0 <locked>
  400cd1:	sub    $0x1,%eax
  400cd4:	mov    %eax,0x2013f6(%rip)        # 6020d0 <locked>
  400cda:	mov    0x2013f0(%rip),%eax        # 6020d0 <locked>
  400ce0:	sub    $0x1,%eax
  400ce3:	mov    %eax,0x2013e7(%rip)        # 6020d0 <locked>
  400ce9:	mov    0x2013e1(%rip),%eax        # 6020d0 <locked>
  400cef:	sub    $0x1,%eax
  400cf2:	mov    %eax,0x2013d8(%rip)        # 6020d0 <locked>
  400cf8:	mov    0x2013d2(%rip),%eax        # 6020d0 <locked>
  400cfe:	sub    $0x1,%eax
  400d01:	mov    %eax,0x2013c9(%rip)        # 6020d0 <locked>
  400d07:	mov    0x2013c3(%rip),%eax        # 6020d0 <locked>
  400d0d:	sub    $0x1,%eax
  400d10:	mov    %eax,0x2013ba(%rip)        # 6020d0 <locked>
  400d16:	mov    0x2013b4(%rip),%eax        # 6020d0 <locked>
  400d1c:	sub    $0x1,%eax
  400d1f:	mov    %eax,0x2013ab(%rip)        # 6020d0 <locked>
  400d25:	movl   $0x0,(%r8)
  400d2c:	mov    %edi,%eax
  400d2e:	xchg   %eax,0x20138c(%rip)        # 6020c0 <lock>
  400d34:	cmp    $0x1,%eax
  400d37:	mov    $0x200,%edx
  400d3c:	jne    400d6f <thread+0x23f>
  400d3e:	xchg   %ax,%ax
  400d40:	xor    %eax,%eax
  400d42:	test   %edx,%edx
  400d44:	je     400d57 <thread+0x227>
  400d46:	nopw   %cs:0x0(%rax,%rax,1)
  400d50:	add    $0x1,%eax
  400d53:	cmp    %edx,%eax
  400d55:	jne    400d50 <thread+0x220>
  400d57:	cmp    $0xffffe,%edx
  400d5d:	mov    %edi,%eax
  400d5f:	setbe  %cl
  400d62:	shl    %cl,%edx
  400d64:	xchg   %eax,0x201356(%rip)        # 6020c0 <lock>
  400d6a:	cmp    $0x1,%eax
  400d6d:	je     400d40 <thread+0x210>
  400d6f:	mov    0x20135b(%rip),%esi        # 6020d0 <locked>
  400d75:	test   %esi,%esi
  400d77:	jne    400d92 <thread+0x262>
  400d79:	movl   $0x0,(%r8)
  400d80:	sub    $0x1,%r9d
  400d84:	jne    400b96 <thread+0x66>
  400d8a:	sub    $0xffffffffffffff80,%rsp
  400d8e:	xor    %eax,%eax
  400d90:	pop    %rbx
  400d91:	retq   
  400d92:	lea    0x10f(%rip),%rdi        # 400ea8 <__dso_handle+0x50>
  400d99:	xor    %eax,%eax
  400d9b:	callq  400a80 <ck_error>
  400da0:	lea    0xd9(%rip),%rdi        # 400e80 <__dso_handle+0x28>
  400da7:	xor    %eax,%eax
  400da9:	callq  400a80 <ck_error>
  400dae:	lea    0x243(%rip),%rdi        # 400ff8 <__dso_handle+0x1a0>
  400db5:	callq  400a80 <ck_error>
  400dba:	lea    0x9f(%rip),%rdi        # 400e60 <__dso_handle+0x8>
  400dc1:	callq  400790 <perror@plt>
  400dc6:	mov    $0x1,%edi
  400dcb:	callq  4007c0 <exit@plt>
