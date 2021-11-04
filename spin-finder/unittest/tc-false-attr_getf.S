// TC_OUT
00000000000014f0 <attr_getf>:
    14f0:	push   %r15
    14f2:	push   %r14
    14f4:	mov    %rcx,%r14
    14f7:	push   %r13
    14f9:	push   %r12
    14fb:	mov    %rsi,%r13
    14fe:	push   %rbp
    14ff:	push   %rbx
    1500:	mov    %r8d,%r12d
    1503:	xor    %ebp,%ebp
    1505:	sub    $0x138,%rsp
    150c:	mov    %fs:0x28,%rax
    1515:	mov    %rax,0x128(%rsp)
    151d:	xor    %eax,%eax
    151f:	lea    0x10(%rsp),%rbx
    1524:	mov    %edi,0x8(%rsp)
    1528:	mov    %rdx,(%rsp)
    152c:	mov    %ebp,%ecx
    152e:	mov    %r12d,%edx
    1531:	mov    %r13,%rsi
    1534:	mov    %rbx,%rdi
    1537:	callq  11c0 <__cxa_finalize@plt+0x110>
    153c:	test   %eax,%eax
    153e:	js     1572 <attr_getf+0x82>
    1540:	movslq (%r14),%rcx
    1543:	mov    (%rsp),%rdx
    1547:	mov    %rbx,%rsi
    154a:	mov    0x8(%rsp),%edi
    154e:	callq  30c0 <fgetxattr>
    1553:	test   %eax,%eax
    1555:	mov    %rax,%r15
    1558:	mov    %eax,0xc(%rsp)
    155c:	jns    15b0 <attr_getf+0xc0>
    155e:	callq  f70 <__errno_location@plt>
    1563:	mov    (%rax),%eax
    1565:	cmp    $0x5f,%eax
    1568:	je     15a0 <attr_getf+0xb0>
    156a:	cmp    $0x3d,%eax
    156d:	je     15a0 <attr_getf+0xb0>
    156f:	mov    %r15d,%eax
    1572:	mov    0x128(%rsp),%rdx
    157a:	xor    %fs:0x28,%rdx
    1583:	jne    15b7 <attr_getf+0xc7>
    1585:	add    $0x138,%rsp
    158c:	pop    %rbx
    158d:	pop    %rbp
    158e:	pop    %r12
    1590:	pop    %r13
    1592:	pop    %r14
    1594:	pop    %r15
    1596:	retq   
    1597:	nopw   0x0(%rax,%rax,1)
    15a0:	cmp    $0x1,%ebp
    15a3:	jne    15bc <attr_getf+0xcc>
    15a5:	mov    0xc(%rsp),%eax
    15a9:	jmp    1572 <attr_getf+0x82>
    15ab:	nopl   0x0(%rax,%rax,1)
    15b0:	mov    %eax,(%r14)
    15b3:	xor    %eax,%eax
    15b5:	jmp    1572 <attr_getf+0x82>
    15b7:	callq  ff0 <__stack_chk_fail@plt>
    15bc:	mov    $0x1,%ebp
    15c1:	jmpq   152c <attr_getf+0x3c>
    15c6:	nopw   %cs:0x0(%rax,%rax,1)
