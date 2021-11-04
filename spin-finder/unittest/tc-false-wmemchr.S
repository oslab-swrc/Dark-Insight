// TC_OUT
0000000000000000 <wmemchr>:
   0:	jmp    23 <wmemchr+0x23>
   2:	nopw   0x0(%rax,%rax,1)
   8:	cmp    %esi,(%rdi)
   a:	je     58 <wmemchr+0x58>
   c:	cmp    %esi,0x4(%rdi)
   f:	je     60 <wmemchr+0x60>
  11:	cmp    %esi,0x8(%rdi)
  14:	je     68 <wmemchr+0x68>
  16:	cmp    %esi,0xc(%rdi)
  19:	je     70 <wmemchr+0x70>
  1b:	add    $0x10,%rdi
  1f:	sub    $0x4,%rdx
  23:	cmp    $0x3,%rdx
  27:	ja     8 <wmemchr+0x8>
  29:	xor    %eax,%eax
  2b:	test   %rdx,%rdx
  2e:	je     5b <wmemchr+0x5b>
  30:	cmp    %esi,(%rdi)
  32:	je     58 <wmemchr+0x58>
  34:	cmp    $0x1,%rdx
  38:	je     5b <wmemchr+0x5b>
  3a:	cmp    %esi,0x4(%rdi)
  3d:	je     60 <wmemchr+0x60>
  3f:	cmp    $0x2,%rdx
  43:	lea    0x8(%rdi),%rcx
  47:	je     5b <wmemchr+0x5b>
  49:	cmp    %esi,0x8(%rdi)
  4c:	cmove  %rcx,%rax
  50:	retq   
  51:	nopl   0x0(%rax)
  58:	mov    %rdi,%rax
  5b:	repz retq 
  5d:	nopl   (%rax)
  60:	lea    0x4(%rdi),%rax
  64:	retq   
  65:	nopl   (%rax)
  68:	lea    0x8(%rdi),%rax
  6c:	retq   
  6d:	nopl   (%rax)
  70:	lea    0xc(%rdi),%rax
  74:	retq   
