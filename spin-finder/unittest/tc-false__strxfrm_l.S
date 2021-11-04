// TC_OUT
0000000000099830 <__strxfrm_l>:
   99830:	push   %rbp
   99831:	mov    %rsp,%rbp
   99834:	push   %r15
   99836:	push   %r14
   99838:	push   %r13
   9983a:	push   %r12
   9983c:	mov    %rdi,%r15
   9983f:	push   %rbx
   99840:	mov    %rsi,%rdi
   99843:	sub    $0xc8,%rsp
   9984a:	mov    0x18(%rcx),%rax
   9984e:	mov    %rsi,-0x90(%rbp)
   99855:	mov    %rdx,-0x68(%rbp)
   99859:	mov    0x40(%rax),%ebx
   9985c:	test   %rbx,%rbx
   9985f:	mov    %rbx,-0x80(%rbp)
   99863:	jne    998a7 <__strxfrm_l+0x77>
   99865:	mov    %rdx,%r14
   99868:	callq  8d020 <strlen>
   9986d:	test   %r14,%r14
   99870:	mov    %rax,%r13
   99873:	je     99895 <__strxfrm_l+0x65>
   99875:	lea    0x1(%r13),%rax
   99879:	mov    %r14,%rdi
   9987c:	mov    -0x90(%rbp),%rsi
   99883:	cmp    %r14,%rax
   99886:	cmovbe %rax,%rdi
   9988a:	mov    %rdi,%rdx
   9988d:	mov    %r15,%rdi
   99890:	callq  a0640 <__GI___stpncpy>
   99895:	lea    -0x28(%rbp),%rsp
   99899:	mov    %r13,%rax
   9989c:	pop    %rbx
   9989d:	pop    %r12
   9989f:	pop    %r13
   998a1:	pop    %r14
   998a3:	pop    %r15
   998a5:	pop    %rbp
   998a6:	retq   
   998a7:	cmpb   $0x0,(%rsi)
   998aa:	jne    998bc <__strxfrm_l+0x8c>
   998ac:	xor    %r13d,%r13d
   998af:	cmpq   $0x0,-0x68(%rbp)
   998b4:	je     99895 <__strxfrm_l+0x65>
   998b6:	movb   $0x0,(%r15)
   998ba:	jmp    99895 <__strxfrm_l+0x65>
   998bc:	mov    0x48(%rax),%rdi
   998c0:	mov    0x60(%rax),%rbx
   998c4:	mov    0x58(%rax),%r14
   998c8:	mov    %rdi,-0xb8(%rbp)
   998cf:	mov    0x50(%rax),%rdi
   998d3:	mov    0x68(%rax),%rax
   998d7:	mov    %rbx,-0x70(%rbp)
   998db:	test   $0x3,%dil
   998df:	mov    %rdi,-0x48(%rbp)
   998e3:	mov    %rax,-0x78(%rbp)
   998e7:	jne    99b1b <__strxfrm_l+0x2eb>
   998ed:	testb  $0x3,-0x78(%rbp)
   998f1:	jne    99afc <__strxfrm_l+0x2cc>
   998f7:	sub    $0x4010,%rsp
   998fe:	mov    -0x90(%rbp),%rcx
   99905:	movq   $0x0,-0x60(%rbp)
   9990d:	lea    0xf(%rsp),%rax
   99912:	sub    $0x1010,%rsp
   99919:	mov    $0x4,%r13d
   9991f:	and    $0xfffffffffffffff0,%rax
   99923:	mov    %rax,-0x50(%rbp)
   99927:	lea    0xf(%rsp),%rax
   9992c:	and    $0xfffffffffffffff0,%rax
   99930:	mov    %rax,-0x58(%rbp)
   99934:	jmp    99981 <__strxfrm_l+0x151>
   99936:	nopw   %cs:0x0(%rax,%rax,1)
   99940:	mov    %r10,%rcx
   99943:	mov    -0x60(%rbp),%rbx
   99947:	mov    -0x58(%rbp),%rsi
   9994b:	mov    %edi,%eax
   9994d:	sar    $0x18,%eax
   99950:	and    $0xffffff,%edi
   99956:	cmpb   $0x0,(%rcx)
   99959:	mov    %al,(%rsi,%rbx,1)
   9995c:	mov    -0x50(%rbp),%rax
   99960:	mov    %edi,(%rax,%rbx,4)
   99963:	lea    0x1(%rbx),%rax
   99967:	je     9d631 <__strxfrm_l+0x3e01>
   9996d:	cmp    $0xfff,%rax
   99973:	je     99b3a <__strxfrm_l+0x30a>
   99979:	mov    -0x48(%rbp),%rdi
   9997d:	mov    %rax,-0x60(%rbp)
   99981:	movzbl (%rcx),%eax
   99984:	lea    0x1(%rcx),%r10
   99988:	movslq (%rdi,%rax,4),%rax
   9998c:	test   %rax,%rax
   9998f:	mov    %rax,%rdi
   99992:	jns    99940 <__strxfrm_l+0x110>
   99994:	mov    -0x70(%rbp),%rdx
   99998:	sub    %rax,%rdx
   9999b:	movslq (%rdx),%rdi
   9999e:	lea    0x5(%rdx),%rsi
   999a2:	movzbl 0x4(%rdx),%eax
   999a6:	test   %edi,%edi
   999a8:	js     99a0a <__strxfrm_l+0x1da>
   999aa:	test   %rax,%rax
   999ad:	je     99aee <__strxfrm_l+0x2be>
   999b3:	movzbl 0x1(%rcx),%ebx
   999b7:	cmp    %bl,0x5(%rdx)
   999ba:	jne    999e0 <__strxfrm_l+0x1b0>
   999bc:	xor    %edx,%edx
   999be:	jmp    999ca <__strxfrm_l+0x19a>
   999c0:	movzbl 0x1(%rcx,%rdx,1),%ebx
   999c5:	cmp    %bl,(%rsi,%rdx,1)
   999c8:	jne    999e0 <__strxfrm_l+0x1b0>
   999ca:	add    $0x1,%rdx
   999ce:	cmp    %rdx,%rax
   999d1:	jne    999c0 <__strxfrm_l+0x190>
   999d3:	lea    (%r10,%rdx,1),%rcx
   999d7:	jmpq   99943 <__strxfrm_l+0x113>
   999dc:	nopl   0x0(%rax)
   999e0:	lea    (%rsi,%rax,1),%rdx
   999e4:	add    $0x1,%rax
   999e8:	mov    %r13,%rsi
   999eb:	and    $0x3,%eax
   999ee:	sub    %rax,%rsi
   999f1:	add    %rdx,%rsi
   999f4:	test   %rax,%rax
   999f7:	cmovne %rsi,%rdx
   999fb:	movslq (%rdx),%rdi
   999fe:	lea    0x5(%rdx),%rsi
   99a02:	movzbl 0x4(%rdx),%eax
   99a06:	test   %edi,%edi
   99a08:	jns    999aa <__strxfrm_l+0x17a>
   99a0a:	test   %rax,%rax
   99a0d:	je     99af5 <__strxfrm_l+0x2c5>
   99a13:	movzbl 0x5(%rdx),%r11d
   99a18:	movzbl 0x1(%rcx),%r8d
   99a1d:	cmp    %r11b,%r8b
   99a20:	jne    99a53 <__strxfrm_l+0x223>
   99a22:	xor    %edx,%edx
   99a24:	jmp    99a35 <__strxfrm_l+0x205>
   99a26:	movzbl (%rsi,%rdx,1),%ebx
   99a2a:	movzbl 0x1(%rcx,%rdx,1),%r9d
   99a30:	cmp    %r9b,%bl
   99a33:	jne    99a59 <__strxfrm_l+0x229>
   99a35:	add    $0x1,%rdx
   99a39:	cmp    %rdx,%rax
   99a3c:	jne    99a26 <__strxfrm_l+0x1f6>
   99a3e:	xor    %eax,%eax
   99a40:	sub    %rdi,%rax
   99a43:	mov    -0x78(%rbp),%rdi
   99a47:	lea    (%r10,%rdx,1),%rcx
   99a4b:	mov    (%rdi,%rax,4),%edi
   99a4e:	jmpq   99943 <__strxfrm_l+0x113>
   99a53:	mov    %r11d,%ebx
   99a56:	mov    %r8d,%r9d
   99a59:	cmp    %r9b,%bl
   99a5c:	ja     99ac8 <__strxfrm_l+0x298>
   99a5e:	lea    (%rsi,%rax,1),%r12
   99a62:	movzbl (%r12),%r9d
   99a67:	cmp    %r9b,%r8b
   99a6a:	jne    99ae1 <__strxfrm_l+0x2b1>
   99a6c:	xor    %edx,%edx
   99a6e:	jmp    99a7f <__strxfrm_l+0x24f>
   99a70:	movzbl (%r12,%rdx,1),%r9d
   99a75:	movzbl 0x1(%rcx,%rdx,1),%ebx
   99a7a:	cmp    %bl,%r9b
   99a7d:	jne    99ae4 <__strxfrm_l+0x2b4>
   99a7f:	add    $0x1,%rdx
   99a83:	cmp    %rdx,%rax
   99a86:	jne    99a70 <__strxfrm_l+0x240>
   99a88:	xor    %r9d,%r9d
   99a8b:	cmp    %r11b,%r8b
   99a8e:	jne    99aa0 <__strxfrm_l+0x270>
   99a90:	add    $0x1,%r9
   99a94:	movzbl 0x1(%rcx,%r9,1),%eax
   99a9a:	cmp    %al,(%rsi,%r9,1)
   99a9e:	je     99a90 <__strxfrm_l+0x260>
   99aa0:	xor    %eax,%eax
   99aa2:	movzbl 0x1(%rcx,%r9,1),%r8d
   99aa8:	movzbl (%rsi,%r9,1),%r11d
   99aad:	shl    $0x8,%rax
   99ab1:	add    $0x1,%r9
   99ab5:	sub    %r11d,%r8d
   99ab8:	movslq %r8d,%r8
   99abb:	add    %r8,%rax
   99abe:	cmp    %rdx,%r9
   99ac1:	jb     99aa2 <__strxfrm_l+0x272>
   99ac3:	jmpq   99a40 <__strxfrm_l+0x210>
   99ac8:	add    %rax,%rax
   99acb:	lea    0x4(%rax),%rdx
   99acf:	add    $0x1,%rax
   99ad3:	and    $0x3,%eax
   99ad6:	sub    %rax,%rdx
   99ad9:	add    %rsi,%rdx
   99adc:	jmpq   9999b <__strxfrm_l+0x16b>
   99ae1:	mov    %r8d,%ebx
   99ae4:	cmp    %bl,%r9b
   99ae7:	jb     99ac8 <__strxfrm_l+0x298>
   99ae9:	mov    %rax,%rdx
   99aec:	jmp    99a88 <__strxfrm_l+0x258>
   99aee:	xor    %edx,%edx
   99af0:	jmpq   999d3 <__strxfrm_l+0x1a3>
   99af5:	xor    %edx,%edx
   99af7:	jmpq   99a40 <__strxfrm_l+0x210>
   99afc:	lea    0xf4e6d(%rip),%rcx        # 18e970 <__PRETTY_FUNCTION__.7858>
   99b03:	lea    0xf1189(%rip),%rsi        # 18ac93 <__func__.11632+0x1cf>
   99b0a:	lea    0xf4e17(%rip),%rdi        # 18e928 <__PRETTY_FUNCTION__.7719+0x50>
   99b11:	mov    $0x2c4,%edx
   99b16:	callq  2dea0 <__assert_fail>
   99b1b:	lea    0xf4e4e(%rip),%rcx        # 18e970 <__PRETTY_FUNCTION__.7858>
   99b22:	lea    0xf116a(%rip),%rsi        # 18ac93 <__func__.11632+0x1cf>
   99b29:	lea    0xf4db8(%rip),%rdi        # 18e8e8 <__PRETTY_FUNCTION__.7719+0x10>
   99b30:	mov    $0x2c1,%edx
   99b35:	callq  2dea0 <__assert_fail>
   99b3a:	movb   $0x0,0xfff(%rsi)
   99b41:	movq   $0x0,-0xa0(%rbp)
   99b4c:	mov    %r15,%r13
   99b4f:	movq   $0x0,-0xb0(%rbp)
   99b5a:	mov    -0x90(%rbp),%rax
   99b61:	mov    -0x48(%rbp),%rdi
   99b65:	mov    -0xa0(%rbp),%r15d
   99b6c:	movzbl (%rax),%edx
   99b6f:	mov    %rdx,%rax
   99b72:	movslq (%rdi,%rdx,4),%rdx
   99b76:	test   %rdx,%rdx
   99b79:	mov    %rdx,%r10
   99b7c:	js     9d27a <__strxfrm_l+0x3a4a>
   99b82:	mov    %r10d,%edx
   99b85:	mov    -0xb8(%rbp),%rdi
   99b8c:	movslq %r15d,%rcx
   99b8f:	sar    $0x18,%edx
   99b92:	mov    -0x90(%rbp),%rbx
   99b99:	movzbl %dl,%edx
   99b9c:	imul   -0x80(%rbp),%rdx
   99ba1:	add    %rdi,%rdx
   99ba4:	testb  $0x4,(%rdx,%rcx,1)
   99ba8:	je     9ba48 <__strxfrm_l+0x2218>
   99bae:	add    -0xa0(%rbp),%rdi
   99bb5:	mov    -0xb0(%rbp),%rsi
   99bbc:	xor    %r12d,%r12d
   99bbf:	test   %al,%al
   99bc1:	movl   $0x1,-0x60(%rbp)
   99bc8:	movq   $0x0,-0x50(%rbp)
   99bd0:	mov    %rsi,-0x58(%rbp)
   99bd4:	mov    %rdi,-0xd8(%rbp)
   99bdb:	mov    %r13,%rdi
   99bde:	mov    %r12,%r13
   99be1:	mov    %rdi,%r12
   99be4:	je     99e3e <__strxfrm_l+0x60e>
   99bea:	lea    0x1(%rbx),%rdi
   99bee:	mov    %rdi,-0xc0(%rbp)
   99bf5:	mov    -0x48(%rbp),%rdi
   99bf9:	movslq (%rdi,%rax,4),%rax
   99bfd:	test   %rax,%rax
   99c00:	mov    %rax,%r9
   99c03:	js     9a8fc <__strxfrm_l+0x10cc>
   99c09:	mov    %r9d,%eax
   99c0c:	and    $0xffffff,%r9d
   99c13:	shr    $0x18,%eax
   99c16:	test   %r15d,%r15d
   99c19:	mov    %eax,%ecx
   99c1b:	lea    0x1(%r9),%eax
   99c1f:	movslq %r9d,%r9
   99c22:	mov    %eax,%esi
   99c24:	mov    %eax,-0xd0(%rbp)
   99c2a:	movzbl (%r14,%r9,1),%eax
   99c2f:	mov    %rax,%rdx
   99c32:	mov    %rax,-0x88(%rbp)
   99c39:	jle    99c5f <__strxfrm_l+0x42f>
   99c3b:	xor    %eax,%eax
   99c3d:	add    %esi,%edx
   99c3f:	add    $0x1,%eax
   99c42:	lea    0x1(%rdx),%esi
   99c45:	cmp    %eax,%r15d
   99c48:	movslq %edx,%rdx
   99c4b:	movzbl (%r14,%rdx,1),%edx
   99c50:	jne    99c3d <__strxfrm_l+0x40d>
   99c52:	mov    %esi,-0xd0(%rbp)
   99c58:	mov    %rdx,-0x88(%rbp)
   99c5f:	movzbl %cl,%eax
   99c62:	mov    -0xd8(%rbp),%rdi
   99c69:	imul   -0x80(%rbp),%rax
   99c6e:	testb  $0x1,(%rdi,%rax,1)
   99c72:	je     9a8c4 <__strxfrm_l+0x1094>
   99c78:	test   %r13,%r13
   99c7b:	je     99dd0 <__strxfrm_l+0x5a0>
   99c81:	cmpq   $0x0,-0x50(%rbp)
   99c86:	je     99dd0 <__strxfrm_l+0x5a0>
   99c8c:	lea    0x1(%r13),%rax
   99c90:	mov    %r12,-0x98(%rbp)
   99c97:	mov    %rax,-0xa8(%rbp)
   99c9e:	movzbl 0x0(%r13),%eax
   99ca3:	mov    -0x48(%rbp),%rdi
   99ca7:	mov    -0xa8(%rbp),%rcx
   99cae:	movslq (%rdi,%rax,4),%rax
   99cb2:	test   %rax,%rax
   99cb5:	mov    %rax,%r8
   99cb8:	js     9a172 <__strxfrm_l+0x942>
   99cbe:	and    $0xffffff,%r8d
   99cc5:	test   %r15d,%r15d
   99cc8:	lea    0x1(%r8),%edx
   99ccc:	movslq %r8d,%r8
   99ccf:	movzbl (%r14,%r8,1),%eax
   99cd4:	jle    99cf4 <__strxfrm_l+0x4c4>
   99cd6:	xor    %esi,%esi
   99cd8:	nopl   0x0(%rax,%rax,1)
   99ce0:	add    %edx,%eax
   99ce2:	add    $0x1,%esi
   99ce5:	lea    0x1(%rax),%edx
   99ce8:	cmp    %esi,%r15d
   99ceb:	cltq   
   99ced:	movzbl (%r14,%rax,1),%eax
   99cf2:	jne    99ce0 <__strxfrm_l+0x4b0>
   99cf4:	cmpq   $0x1,-0x50(%rbp)
   99cf9:	jbe    99d75 <__strxfrm_l+0x545>
   99cfb:	mov    $0x1,%r12d
   99d01:	mov    %r13,-0xc8(%rbp)
   99d08:	nopl   0x0(%rax,%rax,1)
   99d10:	movzbl (%rcx),%eax
   99d13:	mov    -0x48(%rbp),%rdi
   99d17:	lea    0x1(%rcx),%r13
   99d1b:	movslq (%rdi,%rax,4),%rax
   99d1f:	test   %rax,%rax
   99d22:	mov    %rax,%rdi
   99d25:	js     99fc2 <__strxfrm_l+0x792>
   99d2b:	mov    %r13,%rcx
   99d2e:	and    $0xffffff,%edi
   99d34:	test   %r15d,%r15d
   99d37:	lea    0x1(%rdi),%edx
   99d3a:	movslq %edi,%rdi
   99d3d:	movzbl (%r14,%rdi,1),%eax
   99d42:	jle    99d64 <__strxfrm_l+0x534>
   99d44:	xor    %esi,%esi
   99d46:	nopw   %cs:0x0(%rax,%rax,1)
   99d50:	add    %edx,%eax
   99d52:	add    $0x1,%esi
   99d55:	lea    0x1(%rax),%edx
   99d58:	cmp    %esi,%r15d
   99d5b:	cltq   
   99d5d:	movzbl (%r14,%rax,1),%eax
   99d62:	jne    99d50 <__strxfrm_l+0x520>
   99d64:	add    $0x1,%r12
   99d68:	cmp    -0x50(%rbp),%r12
   99d6c:	jne    99d10 <__strxfrm_l+0x4e0>
   99d6e:	mov    -0xc8(%rbp),%r13
   99d75:	test   %rax,%rax
   99d78:	je     9a162 <__strxfrm_l+0x932>
   99d7e:	cmpl   $0x7f,-0x60(%rbp)
   99d82:	jg     9a2f2 <__strxfrm_l+0xac2>
   99d88:	movzbl -0x60(%rbp),%edi
   99d8c:	mov    %dil,-0x40(%rbp)
   99d90:	mov    -0x58(%rbp),%rdi
   99d94:	add    $0x1,%rdi
   99d98:	lea    (%rdi,%rax,1),%rcx
   99d9c:	cmp    %rcx,-0x68(%rbp)
   99da0:	ja     9b061 <__strxfrm_l+0x1831>
   99da6:	mov    $0x1,%r9d
   99dac:	add    -0x58(%rbp),%rax
   99db0:	movl   $0x1,-0x60(%rbp)
   99db7:	add    %r9,%rax
   99dba:	mov    %rax,-0x58(%rbp)
   99dbe:	subq   $0x1,-0x50(%rbp)
   99dc3:	jne    99c9e <__strxfrm_l+0x46e>
   99dc9:	mov    -0x98(%rbp),%r12
   99dd0:	cmpq   $0x0,-0x88(%rbp)
   99dd8:	je     9b055 <__strxfrm_l+0x1825>
   99dde:	cmpl   $0x7f,-0x60(%rbp)
   99de2:	jg     9aa72 <__strxfrm_l+0x1242>
   99de8:	movzbl -0x60(%rbp),%eax
   99dec:	mov    %al,-0x40(%rbp)
   99def:	mov    -0x58(%rbp),%rax
   99df3:	lea    0x1(%rax),%rcx
   99df7:	mov    -0x88(%rbp),%rax
   99dfe:	add    %rcx,%rax
   99e01:	cmp    %rax,-0x68(%rbp)
   99e05:	ja     9f84a <__strxfrm_l+0x601a>
   99e0b:	mov    $0x1,%edi
   99e10:	mov    -0x58(%rbp),%rax
   99e14:	add    -0x88(%rbp),%rax
   99e1b:	xor    %r13d,%r13d
   99e1e:	movl   $0x1,-0x60(%rbp)
   99e25:	add    %rdi,%rax
   99e28:	mov    %rax,-0x58(%rbp)
   99e2c:	mov    -0xc0(%rbp),%rbx
   99e33:	movzbl (%rbx),%eax
   99e36:	test   %al,%al
   99e38:	jne    99bea <__strxfrm_l+0x3ba>
   99e3e:	mov    %r12,%rax
   99e41:	mov    %r13,%r12
   99e44:	test   %r12,%r12
   99e47:	mov    %rax,%r13
   99e4a:	je     99f88 <__strxfrm_l+0x758>
   99e50:	cmpq   $0x0,-0x50(%rbp)
   99e55:	je     99f88 <__strxfrm_l+0x758>
   99e5b:	lea    0x1(%r12),%rax
   99e60:	mov    %rax,-0x88(%rbp)
   99e67:	movzbl (%r12),%eax
   99e6c:	mov    -0x48(%rbp),%rdi
   99e70:	mov    -0x88(%rbp),%rcx
   99e77:	movslq (%rdi,%rax,4),%rax
   99e7b:	test   %rax,%rax
   99e7e:	mov    %rax,%rsi
   99e81:	js     9b21a <__strxfrm_l+0x19ea>
   99e87:	and    $0xffffff,%esi
   99e8d:	test   %r15d,%r15d
   99e90:	lea    0x1(%rsi),%edx
   99e93:	movslq %esi,%rsi
   99e96:	movzbl (%r14,%rsi,1),%eax
   99e9b:	jle    99eb3 <__strxfrm_l+0x683>
   99e9d:	xor    %esi,%esi
   99e9f:	add    %edx,%eax
   99ea1:	add    $0x1,%esi
   99ea4:	lea    0x1(%rax),%edx
   99ea7:	cmp    %esi,%r15d
   99eaa:	cltq   
   99eac:	movzbl (%r14,%rax,1),%eax
   99eb1:	jne    99e9f <__strxfrm_l+0x66f>
   99eb3:	cmpq   $0x1,-0x50(%rbp)
   99eb8:	jbe    99f34 <__strxfrm_l+0x704>
   99eba:	mov    $0x1,%ebx
   99ebf:	mov    %r12,-0x98(%rbp)
   99ec6:	mov    %r13,-0xa8(%rbp)
   99ecd:	movzbl (%rcx),%eax
   99ed0:	mov    -0x48(%rbp),%rdi
   99ed4:	lea    0x1(%rcx),%r13
   99ed8:	movslq (%rdi,%rax,4),%rax
   99edc:	test   %rax,%rax
   99edf:	mov    %rax,%rdi
   99ee2:	js     9b07e <__strxfrm_l+0x184e>
   99ee8:	mov    %r13,%rcx
   99eeb:	and    $0xffffff,%edi
   99ef1:	test   %r15d,%r15d
   99ef4:	lea    0x1(%rdi),%edx
   99ef7:	movslq %edi,%rdi
   99efa:	movzbl (%r14,%rdi,1),%eax
   99eff:	jle    99f1c <__strxfrm_l+0x6ec>
   99f01:	xor    %esi,%esi
   99f03:	nopl   0x0(%rax,%rax,1)
   99f08:	add    %edx,%eax
   99f0a:	add    $0x1,%esi
   99f0d:	lea    0x1(%rax),%edx
   99f10:	cmp    %esi,%r15d
   99f13:	cltq   
   99f15:	movzbl (%r14,%rax,1),%eax
   99f1a:	jne    99f08 <__strxfrm_l+0x6d8>
   99f1c:	add    $0x1,%rbx
   99f20:	cmp    -0x50(%rbp),%rbx
   99f24:	jne    99ecd <__strxfrm_l+0x69d>
   99f26:	mov    -0x98(%rbp),%r12
   99f2d:	mov    -0xa8(%rbp),%r13
   99f34:	test   %rax,%rax
   99f37:	je     9b20a <__strxfrm_l+0x19da>
   99f3d:	cmpl   $0x7f,-0x60(%rbp)
   99f41:	jg     9b397 <__strxfrm_l+0x1b67>
   99f47:	movzbl -0x60(%rbp),%edi
   99f4b:	mov    %dil,-0x40(%rbp)
   99f4f:	mov    -0x58(%rbp),%rdi
   99f53:	add    $0x1,%rdi
   99f57:	lea    (%rdi,%rax,1),%rcx
   99f5b:	cmp    %rcx,-0x68(%rbp)
   99f5f:	ja     9f890 <__strxfrm_l+0x6060>
   99f65:	mov    $0x1,%r11d
   99f6b:	add    -0x58(%rbp),%rax
   99f6f:	movl   $0x1,-0x60(%rbp)
   99f76:	add    %r11,%rax
   99f79:	mov    %rax,-0x58(%rbp)
   99f7d:	subq   $0x1,-0x50(%rbp)
   99f82:	jne    99e67 <__strxfrm_l+0x637>
   99f88:	mov    -0x58(%rbp),%rdi
   99f8c:	cmp    %rdi,-0x68(%rbp)
   99f90:	ja     9b9e2 <__strxfrm_l+0x21b2>
   99f96:	mov    -0xa0(%rbp),%rax
   99f9d:	lea    0x1(%rdi),%rcx
   99fa1:	add    $0x1,%rax
   99fa5:	cmp    %rax,-0x80(%rbp)
   99fa9:	jbe    9ba0a <__strxfrm_l+0x21da>
   99faf:	mov    %rax,-0xa0(%rbp)
   99fb6:	mov    %rcx,-0xb0(%rbp)
   99fbd:	jmpq   99b5a <__strxfrm_l+0x32a>
   99fc2:	mov    -0x70(%rbp),%rdx
   99fc6:	sub    %rax,%rdx
   99fc9:	movslq (%rdx),%rdi
   99fcc:	lea    0x5(%rdx),%rsi
   99fd0:	movzbl 0x4(%rdx),%eax
   99fd4:	test   %edi,%edi
   99fd6:	js     9a03c <__strxfrm_l+0x80c>
   99fd8:	test   %rax,%rax
   99fdb:	je     9a156 <__strxfrm_l+0x926>
   99fe1:	movzbl 0x1(%rcx),%ebx
   99fe5:	cmp    %bl,0x5(%rdx)
   99fe8:	jne    9a010 <__strxfrm_l+0x7e0>
   99fea:	xor    %edx,%edx
   99fec:	jmp    99ffa <__strxfrm_l+0x7ca>
   99fee:	xchg   %ax,%ax
   99ff0:	movzbl 0x1(%rcx,%rdx,1),%ebx
   99ff5:	cmp    %bl,(%rsi,%rdx,1)
   99ff8:	jne    9a010 <__strxfrm_l+0x7e0>
   99ffa:	add    $0x1,%rdx
   99ffe:	cmp    %rdx,%rax
   9a001:	jne    99ff0 <__strxfrm_l+0x7c0>
   9a003:	lea    0x0(%r13,%rdx,1),%rcx
   9a008:	jmpq   99d2e <__strxfrm_l+0x4fe>
   9a00d:	nopl   (%rax)
   9a010:	lea    (%rsi,%rax,1),%rdx
   9a014:	add    $0x1,%rax
   9a018:	mov    $0x4,%esi
   9a01d:	and    $0x3,%eax
   9a020:	sub    %rax,%rsi
   9a023:	add    %rdx,%rsi
   9a026:	test   %rax,%rax
   9a029:	cmovne %rsi,%rdx
   9a02d:	movslq (%rdx),%rdi
   9a030:	lea    0x5(%rdx),%rsi
   9a034:	movzbl 0x4(%rdx),%eax
   9a038:	test   %edi,%edi
   9a03a:	jns    99fd8 <__strxfrm_l+0x7a8>
   9a03c:	test   %rax,%rax
   9a03f:	je     9a16b <__strxfrm_l+0x93b>
   9a045:	movzbl 0x5(%rdx),%ebx
   9a049:	movzbl 0x1(%rcx),%r11d
   9a04e:	cmp    %r11b,%bl
   9a051:	jne    9a08f <__strxfrm_l+0x85f>
   9a053:	xor    %edx,%edx
   9a055:	jmp    9a070 <__strxfrm_l+0x840>
   9a057:	nopw   0x0(%rax,%rax,1)
   9a060:	movzbl (%rsi,%rdx,1),%r9d
   9a065:	movzbl 0x1(%rcx,%rdx,1),%r8d
   9a06b:	cmp    %r8b,%r9b
   9a06e:	jne    9a098 <__strxfrm_l+0x868>
   9a070:	add    $0x1,%rdx
   9a074:	cmp    %rdx,%rax
   9a077:	jne    9a060 <__strxfrm_l+0x830>
   9a079:	xor    %eax,%eax
   9a07b:	sub    %rdi,%rax
   9a07e:	mov    -0x78(%rbp),%rdi
   9a082:	lea    0x0(%r13,%rdx,1),%rcx
   9a087:	mov    (%rdi,%rax,4),%edi
   9a08a:	jmpq   99d2e <__strxfrm_l+0x4fe>
   9a08f:	mov    %ebx,%r9d
   9a092:	mov    %r11d,%r8d
   9a095:	nopl   (%rax)
   9a098:	cmp    %r8b,%r9b
   9a09b:	ja     9a130 <__strxfrm_l+0x900>
   9a0a1:	lea    (%rsi,%rax,1),%r10
   9a0a5:	movzbl (%r10),%r8d
   9a0a9:	cmp    %r8b,%r11b
   9a0ac:	jne    9a149 <__strxfrm_l+0x919>
   9a0b2:	xor    %edx,%edx
   9a0b4:	jmp    9a0d0 <__strxfrm_l+0x8a0>
   9a0b6:	nopw   %cs:0x0(%rax,%rax,1)
   9a0c0:	movzbl (%r10,%rdx,1),%r8d
   9a0c5:	movzbl 0x1(%rcx,%rdx,1),%r9d
   9a0cb:	cmp    %r9b,%r8b
   9a0ce:	jne    9a14c <__strxfrm_l+0x91c>
   9a0d0:	add    $0x1,%rdx
   9a0d4:	cmp    %rdx,%rax
   9a0d7:	jne    9a0c0 <__strxfrm_l+0x890>
   9a0d9:	xor    %r8d,%r8d
   9a0dc:	cmp    %r11b,%bl
   9a0df:	jne    9a0f8 <__strxfrm_l+0x8c8>
   9a0e1:	nopl   0x0(%rax)
   9a0e8:	add    $0x1,%r8
   9a0ec:	movzbl 0x1(%rcx,%r8,1),%eax
   9a0f2:	cmp    %al,(%rsi,%r8,1)
   9a0f6:	je     9a0e8 <__strxfrm_l+0x8b8>
   9a0f8:	xor    %eax,%eax
   9a0fa:	mov    %rax,%r9
   9a0fd:	nopl   (%rax)
   9a100:	mov    %r9,%rax
   9a103:	movzbl 0x1(%rcx,%r8,1),%r10d
   9a109:	movzbl (%rsi,%r8,1),%r9d
   9a10e:	shl    $0x8,%rax
   9a112:	add    $0x1,%r8
   9a116:	sub    %r9d,%r10d
   9a119:	movslq %r10d,%r9
   9a11c:	add    %rax,%r9
   9a11f:	cmp    %rdx,%r8
   9a122:	jb     9a100 <__strxfrm_l+0x8d0>
   9a124:	mov    %r9,%rax
   9a127:	jmpq   9a07b <__strxfrm_l+0x84b>
   9a12c:	nopl   0x0(%rax)
   9a130:	add    %rax,%rax
   9a133:	lea    0x4(%rax),%rdx
   9a137:	add    $0x1,%rax
   9a13b:	and    $0x3,%eax
   9a13e:	sub    %rax,%rdx
   9a141:	add    %rsi,%rdx
   9a144:	jmpq   99fc9 <__strxfrm_l+0x799>
   9a149:	mov    %r11d,%r9d
   9a14c:	cmp    %r9b,%r8b
   9a14f:	jb     9a130 <__strxfrm_l+0x900>
   9a151:	mov    %rax,%rdx
   9a154:	jmp    9a0d9 <__strxfrm_l+0x8a9>
   9a156:	xor    %edx,%edx
   9a158:	lea    0x0(%r13,%rdx,1),%rcx
   9a15d:	jmpq   99d2e <__strxfrm_l+0x4fe>
   9a162:	addl   $0x1,-0x60(%rbp)
   9a166:	jmpq   99dbe <__strxfrm_l+0x58e>
   9a16b:	xor    %edx,%edx
   9a16d:	jmpq   9a07b <__strxfrm_l+0x84b>
   9a172:	mov    -0x70(%rbp),%rcx
   9a176:	sub    %rax,%rcx
   9a179:	movslq (%rcx),%r8
   9a17c:	lea    0x5(%rcx),%rdx
   9a180:	movzbl 0x4(%rcx),%eax
   9a184:	test   %r8d,%r8d
   9a187:	js     9a1f5 <__strxfrm_l+0x9c5>
   9a189:	test   %rax,%rax
   9a18c:	je     9a8d5 <__strxfrm_l+0x10a5>
   9a192:	movzbl 0x5(%rcx),%edi
   9a196:	cmp    %dil,0x1(%r13)
   9a19a:	jne    9a1c8 <__strxfrm_l+0x998>
   9a19c:	xor    %ecx,%ecx
   9a19e:	jmp    9a1ac <__strxfrm_l+0x97c>
   9a1a0:	movzbl 0x1(%r13,%rcx,1),%edi
   9a1a6:	cmp    %dil,(%rdx,%rcx,1)
   9a1aa:	jne    9a1c8 <__strxfrm_l+0x998>
   9a1ac:	add    $0x1,%rcx
   9a1b0:	cmp    %rcx,%rax
   9a1b3:	jne    9a1a0 <__strxfrm_l+0x970>
   9a1b5:	add    -0xa8(%rbp),%rcx
   9a1bc:	jmpq   99cbe <__strxfrm_l+0x48e>
   9a1c1:	nopl   0x0(%rax)
   9a1c8:	lea    (%rdx,%rax,1),%rcx
   9a1cc:	add    $0x1,%rax
   9a1d0:	mov    $0x4,%edx
   9a1d5:	and    $0x3,%eax
   9a1d8:	sub    %rax,%rdx
   9a1db:	add    %rcx,%rdx
   9a1de:	test   %rax,%rax
   9a1e1:	cmovne %rdx,%rcx
   9a1e5:	movslq (%rcx),%r8
   9a1e8:	lea    0x5(%rcx),%rdx
   9a1ec:	movzbl 0x4(%rcx),%eax
   9a1f0:	test   %r8d,%r8d
   9a1f3:	jns    9a189 <__strxfrm_l+0x959>
   9a1f5:	test   %rax,%rax
   9a1f8:	je     9d366 <__strxfrm_l+0x3b36>
   9a1fe:	movzbl 0x1(%r13),%r9d
   9a203:	movzbl 0x5(%rcx),%r10d
   9a208:	cmp    %r10b,%r9b
   9a20b:	mov    %r9d,%r11d
   9a20e:	jne    9a249 <__strxfrm_l+0xa19>
   9a210:	xor    %ecx,%ecx
   9a212:	jmp    9a227 <__strxfrm_l+0x9f7>
   9a214:	nopl   0x0(%rax)
   9a218:	movzbl (%rdx,%rcx,1),%edi
   9a21c:	movzbl 0x1(%r13,%rcx,1),%esi
   9a222:	cmp    %sil,%dil
   9a225:	jne    9a24f <__strxfrm_l+0xa1f>
   9a227:	add    $0x1,%rcx
   9a22b:	cmp    %rcx,%rax
   9a22e:	jne    9a218 <__strxfrm_l+0x9e8>
   9a230:	xor    %eax,%eax
   9a232:	mov    -0x78(%rbp),%rdi
   9a236:	sub    %r8,%rax
   9a239:	add    -0xa8(%rbp),%rcx
   9a240:	mov    (%rdi,%rax,4),%r8d
   9a244:	jmpq   99cbe <__strxfrm_l+0x48e>
   9a249:	mov    %r10d,%edi
   9a24c:	mov    %r9d,%esi
   9a24f:	cmp    %sil,%dil
   9a252:	ja     9a2ca <__strxfrm_l+0xa9a>
   9a254:	lea    (%rdx,%rax,1),%r12
   9a258:	movzbl (%r12),%ebx
   9a25d:	cmp    %r9b,%bl
   9a260:	jne    9a2e3 <__strxfrm_l+0xab3>
   9a266:	xor    %ecx,%ecx
   9a268:	jmp    9a280 <__strxfrm_l+0xa50>
   9a26a:	nopw   0x0(%rax,%rax,1)
   9a270:	movzbl (%r12,%rcx,1),%edi
   9a275:	movzbl 0x1(%r13,%rcx,1),%esi
   9a27b:	cmp    %sil,%dil
   9a27e:	jne    9a2e8 <__strxfrm_l+0xab8>
   9a280:	add    $0x1,%rcx
   9a284:	cmp    %rcx,%rax
   9a287:	jne    9a270 <__strxfrm_l+0xa40>
   9a289:	mov    %ebx,%r11d
   9a28c:	xor    %esi,%esi
   9a28e:	cmp    %r11b,%r10b
   9a291:	jne    9a2a2 <__strxfrm_l+0xa72>
   9a293:	add    $0x1,%rsi
   9a297:	movzbl 0x1(%r13,%rsi,1),%eax
   9a29d:	cmp    %al,(%rdx,%rsi,1)
   9a2a0:	je     9a293 <__strxfrm_l+0xa63>
   9a2a2:	xor    %eax,%eax
   9a2a4:	shl    $0x8,%rax
   9a2a8:	movzbl (%rdx,%rsi,1),%edi
   9a2ac:	mov    %rax,%r9
   9a2af:	movzbl 0x1(%r13,%rsi,1),%eax
   9a2b5:	add    $0x1,%rsi
   9a2b9:	sub    %edi,%eax
   9a2bb:	cltq   
   9a2bd:	add    %r9,%rax
   9a2c0:	cmp    %rcx,%rsi
   9a2c3:	jb     9a2a4 <__strxfrm_l+0xa74>
   9a2c5:	jmpq   9a232 <__strxfrm_l+0xa02>
   9a2ca:	add    %rax,%rax
   9a2cd:	lea    0x4(%rax),%rcx
   9a2d1:	add    $0x1,%rax
   9a2d5:	and    $0x3,%eax
   9a2d8:	sub    %rax,%rcx
   9a2db:	add    %rdx,%rcx
   9a2de:	jmpq   9a179 <__strxfrm_l+0x949>
   9a2e3:	mov    %r9d,%esi
   9a2e6:	mov    %ebx,%edi
   9a2e8:	cmp    %sil,%dil
   9a2eb:	jb     9a2ca <__strxfrm_l+0xa9a>
   9a2ed:	mov    %rax,%rcx
   9a2f0:	jmp    9a28c <__strxfrm_l+0xa5c>
   9a2f2:	mov    -0x60(%rbp),%edi
   9a2f5:	test   $0xfffff800,%edi
   9a2fb:	je     9f8a8 <__strxfrm_l+0x6078>
   9a301:	test   $0xffff0000,%edi
   9a307:	je     9d4a4 <__strxfrm_l+0x3c74>
   9a30d:	test   $0xffe00000,%edi
   9a313:	je     9d48d <__strxfrm_l+0x3c5d>
   9a319:	and    $0xfc000000,%edi
   9a31f:	mov    -0x60(%rbp),%ebx
   9a322:	cmp    $0x1,%edi
   9a325:	sbb    %r9,%r9
   9a328:	add    $0x6,%r9
   9a32c:	cmp    $0x1,%edi
   9a32f:	sbb    %esi,%esi
   9a331:	add    $0x5,%esi
   9a334:	cmp    $0x1,%edi
   9a337:	sbb    %ecx,%ecx
   9a339:	and    $0xfffffffc,%ecx
   9a33c:	sub    $0x4,%ecx
   9a33f:	mov    %cl,-0x40(%rbp)
   9a342:	mov    %ebx,%ecx
   9a344:	movslq %esi,%rdi
   9a347:	and    $0x3f,%ecx
   9a34a:	or     $0xffffff80,%ecx
   9a34d:	mov    %cl,-0x40(%rbp,%rdi,1)
   9a351:	lea    -0x1(%rsi),%ecx
   9a354:	movslq %ecx,%rdi
   9a357:	mov    %ebx,%ecx
   9a359:	sar    $0x6,%ecx
   9a35c:	and    $0x3f,%ecx
   9a35f:	or     $0xffffff80,%ecx
   9a362:	mov    %cl,-0x40(%rbp,%rdi,1)
   9a366:	mov    %ebx,%ecx
   9a368:	mov    %esi,%edi
   9a36a:	sar    $0xc,%ecx
   9a36d:	sub    $0x2,%edi
   9a370:	je     9a3b0 <__strxfrm_l+0xb80>
   9a372:	and    $0x3f,%ecx
   9a375:	movslq %edi,%rdi
   9a378:	or     $0xffffff80,%ecx
   9a37b:	mov    %cl,-0x40(%rbp,%rdi,1)
   9a37f:	mov    %ebx,%ecx
   9a381:	mov    %esi,%edi
   9a383:	sar    $0x12,%ecx
   9a386:	sub    $0x3,%edi
   9a389:	je     9a3b0 <__strxfrm_l+0xb80>
   9a38b:	and    $0x3f,%ecx
   9a38e:	movslq %edi,%rdi
   9a391:	or     $0xffffff80,%ecx
   9a394:	mov    %cl,-0x40(%rbp,%rdi,1)
   9a398:	mov    %ebx,%ecx
   9a39a:	sar    $0x18,%ecx
   9a39d:	cmp    $0x4,%esi
   9a3a0:	je     9a3b0 <__strxfrm_l+0xb80>
   9a3a2:	and    $0x3f,%ecx
   9a3a5:	or     $0xffffff80,%ecx
   9a3a8:	mov    %cl,-0x3f(%rbp)
   9a3ab:	mov    %ebx,%ecx
   9a3ad:	sar    $0x1e,%ecx
   9a3b0:	mov    -0x58(%rbp),%rdi
   9a3b4:	or     -0x40(%rbp),%cl
   9a3b7:	add    %r9,%rdi
   9a3ba:	lea    (%rax,%rdi,1),%rsi
   9a3be:	cmp    %rsi,-0x68(%rbp)
   9a3c2:	mov    %cl,-0x40(%rbp)
   9a3c5:	jbe    99dac <__strxfrm_l+0x57c>
   9a3cb:	mov    -0x98(%rbp),%rbx
   9a3d2:	mov    -0x58(%rbp),%rsi
   9a3d6:	cmp    $0x2,%r9
   9a3da:	mov    %cl,(%rbx,%rsi,1)
   9a3dd:	movzbl -0x3f(%rbp),%ecx
   9a3e1:	mov    %cl,0x1(%rbx,%rsi,1)
   9a3e5:	je     9a41f <__strxfrm_l+0xbef>
   9a3e7:	movzbl -0x3e(%rbp),%ecx
   9a3eb:	cmp    $0x3,%r9
   9a3ef:	mov    %cl,0x2(%rbx,%rsi,1)
   9a3f3:	je     9a41f <__strxfrm_l+0xbef>
   9a3f5:	movzbl -0x3d(%rbp),%ecx
   9a3f9:	cmp    $0x4,%r9
   9a3fd:	mov    %cl,0x3(%rbx,%rsi,1)
   9a401:	je     9a41f <__strxfrm_l+0xbef>
   9a403:	movzbl -0x3c(%rbp),%ecx
   9a407:	cmp    $0x5,%r9
   9a40b:	mov    %cl,0x4(%rbx,%rsi,1)
   9a40f:	je     9a41f <__strxfrm_l+0xbef>
   9a411:	movzbl -0x3b(%rbp),%ecx
   9a415:	mov    $0x6,%r9d
   9a41b:	mov    %cl,0x5(%rbx,%rsi,1)
   9a41f:	movslq %edx,%rdx
   9a422:	lea    0x10(%rbx,%rdi,1),%rcx
   9a427:	lea    (%rbx,%rdi,1),%r11
   9a42b:	lea    (%r14,%rdx,1),%r8
   9a42f:	cmp    %rcx,%r8
   9a432:	lea    0x10(%r14,%rdx,1),%rcx
   9a437:	setae  %sil
   9a43b:	cmp    %rcx,%r11
   9a43e:	setae  %cl
   9a441:	or     %cl,%sil
   9a444:	je     9a8e3 <__strxfrm_l+0x10b3>
   9a44a:	cmp    $0x14,%rax
   9a44e:	jbe    9a8e3 <__strxfrm_l+0x10b3>
   9a454:	mov    %r8,%rcx
   9a457:	xor    %esi,%esi
   9a459:	neg    %rcx
   9a45c:	and    $0xf,%ecx
   9a45f:	je     9a597 <__strxfrm_l+0xd67>
   9a465:	movzbl (%r8),%esi
   9a469:	cmp    $0x1,%rcx
   9a46d:	mov    %sil,(%r11)
   9a470:	je     9b9d8 <__strxfrm_l+0x21a8>
   9a476:	movzbl 0x1(%r14,%rdx,1),%esi
   9a47c:	cmp    $0x2,%rcx
   9a480:	mov    %sil,0x1(%rbx,%rdi,1)
   9a485:	je     9b9ce <__strxfrm_l+0x219e>
   9a48b:	movzbl 0x2(%r14,%rdx,1),%esi
   9a491:	cmp    $0x3,%rcx
   9a495:	mov    %sil,0x2(%rbx,%rdi,1)
   9a49a:	je     9b9c4 <__strxfrm_l+0x2194>
   9a4a0:	movzbl 0x3(%r14,%rdx,1),%esi
   9a4a6:	cmp    $0x4,%rcx
   9a4aa:	mov    %sil,0x3(%rbx,%rdi,1)
   9a4af:	je     9b9ba <__strxfrm_l+0x218a>
   9a4b5:	movzbl 0x4(%r14,%rdx,1),%esi
   9a4bb:	cmp    $0x5,%rcx
   9a4bf:	mov    %sil,0x4(%rbx,%rdi,1)
   9a4c4:	je     9b9b0 <__strxfrm_l+0x2180>
   9a4ca:	movzbl 0x5(%r14,%rdx,1),%esi
   9a4d0:	cmp    $0x6,%rcx
   9a4d4:	mov    %sil,0x5(%rbx,%rdi,1)
   9a4d9:	je     9b9a6 <__strxfrm_l+0x2176>
   9a4df:	movzbl 0x6(%r14,%rdx,1),%esi
   9a4e5:	cmp    $0x7,%rcx
   9a4e9:	mov    %sil,0x6(%rbx,%rdi,1)
   9a4ee:	je     9b99c <__strxfrm_l+0x216c>
   9a4f4:	movzbl 0x7(%r14,%rdx,1),%esi
   9a4fa:	cmp    $0x8,%rcx
   9a4fe:	mov    %sil,0x7(%rbx,%rdi,1)
   9a503:	je     9b992 <__strxfrm_l+0x2162>
   9a509:	movzbl 0x8(%r14,%rdx,1),%esi
   9a50f:	cmp    $0x9,%rcx
   9a513:	mov    %sil,0x8(%rbx,%rdi,1)
   9a518:	je     9b988 <__strxfrm_l+0x2158>
   9a51e:	movzbl 0x9(%r14,%rdx,1),%esi
   9a524:	cmp    $0xa,%rcx
   9a528:	mov    %sil,0x9(%rbx,%rdi,1)
   9a52d:	je     9b97e <__strxfrm_l+0x214e>
   9a533:	movzbl 0xa(%r14,%rdx,1),%esi
   9a539:	cmp    $0xb,%rcx
   9a53d:	mov    %sil,0xa(%rbx,%rdi,1)
   9a542:	je     9b974 <__strxfrm_l+0x2144>
   9a548:	movzbl 0xb(%r14,%rdx,1),%esi
   9a54e:	cmp    $0xc,%rcx
   9a552:	mov    %sil,0xb(%rbx,%rdi,1)
   9a557:	je     9b96a <__strxfrm_l+0x213a>
   9a55d:	movzbl 0xc(%r14,%rdx,1),%esi
   9a563:	cmp    $0xd,%rcx
   9a567:	mov    %sil,0xc(%rbx,%rdi,1)
   9a56c:	je     9b960 <__strxfrm_l+0x2130>
   9a572:	movzbl 0xd(%r14,%rdx,1),%esi
   9a578:	cmp    $0xf,%rcx
   9a57c:	mov    %sil,0xd(%rbx,%rdi,1)
   9a581:	jne    9b956 <__strxfrm_l+0x2126>
   9a587:	movzbl 0xe(%r14,%rdx,1),%esi
   9a58d:	mov    %sil,0xe(%rbx,%rdi,1)
   9a592:	mov    $0xf,%esi
   9a597:	mov    %rax,%rbx
   9a59a:	lea    -0x1(%rax),%r10
   9a59e:	sub    %rcx,%rbx
   9a5a1:	lea    -0x10(%rbx),%r8
   9a5a5:	sub    %rcx,%r10
   9a5a8:	shr    $0x4,%r8
   9a5ac:	add    $0x1,%r8
   9a5b0:	mov    %r8,%r12
   9a5b3:	shl    $0x4,%r12
   9a5b7:	cmp    $0xe,%r10
   9a5bb:	jbe    9a72a <__strxfrm_l+0xefa>
   9a5c1:	lea    (%rcx,%rdx,1),%r10
   9a5c5:	add    %rdi,%rcx
   9a5c8:	add    -0x98(%rbp),%rcx
   9a5cf:	add    %r14,%r10
   9a5d2:	cmp    $0x1,%r8
   9a5d6:	movdqa (%r10),%xmm0
   9a5db:	movups %xmm0,(%rcx)
   9a5de:	je     9a71e <__strxfrm_l+0xeee>
   9a5e4:	cmp    $0x2,%r8
   9a5e8:	movdqa 0x10(%r10),%xmm0
   9a5ee:	movups %xmm0,0x10(%rcx)
   9a5f2:	je     9a71e <__strxfrm_l+0xeee>
   9a5f8:	cmp    $0x3,%r8
   9a5fc:	movdqa 0x20(%r10),%xmm0
   9a602:	movups %xmm0,0x20(%rcx)
   9a606:	je     9a71e <__strxfrm_l+0xeee>
   9a60c:	cmp    $0x4,%r8
   9a610:	movdqa 0x30(%r10),%xmm0
   9a616:	movups %xmm0,0x30(%rcx)
   9a61a:	je     9a71e <__strxfrm_l+0xeee>
   9a620:	cmp    $0x5,%r8
   9a624:	movdqa 0x40(%r10),%xmm0
   9a62a:	movups %xmm0,0x40(%rcx)
   9a62e:	je     9a71e <__strxfrm_l+0xeee>
   9a634:	cmp    $0x6,%r8
   9a638:	movdqa 0x50(%r10),%xmm0
   9a63e:	movups %xmm0,0x50(%rcx)
   9a642:	je     9a71e <__strxfrm_l+0xeee>
   9a648:	cmp    $0x7,%r8
   9a64c:	movdqa 0x60(%r10),%xmm0
   9a652:	movups %xmm0,0x60(%rcx)
   9a656:	je     9a71e <__strxfrm_l+0xeee>
   9a65c:	cmp    $0x8,%r8
   9a660:	movdqa 0x70(%r10),%xmm0
   9a666:	movups %xmm0,0x70(%rcx)
   9a66a:	je     9a71e <__strxfrm_l+0xeee>
   9a670:	cmp    $0x9,%r8
   9a674:	movdqa 0x80(%r10),%xmm0
   9a67d:	movups %xmm0,0x80(%rcx)
   9a684:	je     9a71e <__strxfrm_l+0xeee>
   9a68a:	cmp    $0xa,%r8
   9a68e:	movdqa 0x90(%r10),%xmm0
   9a697:	movups %xmm0,0x90(%rcx)
   9a69e:	je     9a71e <__strxfrm_l+0xeee>
   9a6a0:	cmp    $0xb,%r8
   9a6a4:	movdqa 0xa0(%r10),%xmm0
   9a6ad:	movups %xmm0,0xa0(%rcx)
   9a6b4:	je     9a71e <__strxfrm_l+0xeee>
   9a6b6:	cmp    $0xc,%r8
   9a6ba:	movdqa 0xb0(%r10),%xmm0
   9a6c3:	movups %xmm0,0xb0(%rcx)
   9a6ca:	je     9a71e <__strxfrm_l+0xeee>
   9a6cc:	cmp    $0xd,%r8
   9a6d0:	movdqa 0xc0(%r10),%xmm0
   9a6d9:	movups %xmm0,0xc0(%rcx)
   9a6e0:	je     9a71e <__strxfrm_l+0xeee>
   9a6e2:	cmp    $0xe,%r8
   9a6e6:	movdqa 0xd0(%r10),%xmm0
   9a6ef:	movups %xmm0,0xd0(%rcx)
   9a6f6:	je     9a71e <__strxfrm_l+0xeee>
   9a6f8:	cmp    $0xf,%r8
   9a6fc:	movdqa 0xe0(%r10),%xmm0
   9a705:	movups %xmm0,0xe0(%rcx)
   9a70c:	je     9a71e <__strxfrm_l+0xeee>
   9a70e:	movdqa 0xf0(%r10),%xmm0
   9a717:	movups %xmm0,0xf0(%rcx)
   9a71e:	add    %r12,%rsi
   9a721:	cmp    %rbx,%r12
   9a724:	je     99dac <__strxfrm_l+0x57c>
   9a72a:	lea    (%r14,%rsi,1),%rcx
   9a72e:	movzbl (%rcx,%rdx,1),%ecx
   9a732:	mov    %cl,(%r11,%rsi,1)
   9a736:	lea    0x1(%rsi),%rcx
   9a73a:	cmp    %rcx,%rax
   9a73d:	jbe    99dac <__strxfrm_l+0x57c>
   9a743:	lea    (%r14,%rcx,1),%r8
   9a747:	lea    0x2(%rsi),%rcx
   9a74b:	movzbl (%r8,%rdx,1),%r8d
   9a750:	cmp    %rcx,%rax
   9a753:	mov    %r8b,0x1(%rsi,%r11,1)
   9a758:	jbe    99dac <__strxfrm_l+0x57c>
   9a75e:	lea    (%r14,%rcx,1),%r8
   9a762:	lea    0x3(%rsi),%rcx
   9a766:	movzbl (%r8,%rdx,1),%r8d
   9a76b:	cmp    %rcx,%rax
   9a76e:	mov    %r8b,0x2(%rsi,%r11,1)
   9a773:	jbe    99dac <__strxfrm_l+0x57c>
   9a779:	lea    (%r14,%rcx,1),%r8
   9a77d:	lea    0x4(%rsi),%rcx
   9a781:	movzbl (%r8,%rdx,1),%r8d
   9a786:	cmp    %rcx,%rax
   9a789:	mov    %r8b,0x3(%rsi,%r11,1)
   9a78e:	jbe    99dac <__strxfrm_l+0x57c>
   9a794:	lea    (%r14,%rcx,1),%r8
   9a798:	lea    0x5(%rsi),%rcx
   9a79c:	movzbl (%r8,%rdx,1),%r8d
   9a7a1:	cmp    %rax,%rcx
   9a7a4:	mov    %r8b,0x4(%rsi,%r11,1)
   9a7a9:	jae    99dac <__strxfrm_l+0x57c>
   9a7af:	mov    -0x98(%rbp),%rbx
   9a7b6:	lea    (%rbx,%rcx,1),%r8
   9a7ba:	add    %r14,%rcx
   9a7bd:	movzbl (%rcx,%rdx,1),%ecx
   9a7c1:	mov    %cl,(%r8,%rdi,1)
   9a7c5:	lea    0x6(%rsi),%rcx
   9a7c9:	cmp    %rax,%rcx
   9a7cc:	jae    99dac <__strxfrm_l+0x57c>
   9a7d2:	lea    (%rbx,%rcx,1),%r8
   9a7d6:	add    %r14,%rcx
   9a7d9:	movzbl (%rcx,%rdx,1),%ecx
   9a7dd:	mov    %cl,(%r8,%rdi,1)
   9a7e1:	lea    0x7(%rsi),%rcx
   9a7e5:	cmp    %rax,%rcx
   9a7e8:	jae    99dac <__strxfrm_l+0x57c>
   9a7ee:	lea    (%rbx,%rcx,1),%r8
   9a7f2:	add    %r14,%rcx
   9a7f5:	movzbl (%rcx,%rdx,1),%ecx
   9a7f9:	mov    %cl,(%r8,%rdi,1)
   9a7fd:	lea    0x8(%rsi),%rcx
   9a801:	cmp    %rcx,%rax
   9a804:	jbe    99dac <__strxfrm_l+0x57c>
   9a80a:	lea    (%r14,%rcx,1),%r8
   9a80e:	lea    0x9(%rsi),%rcx
   9a812:	movzbl (%r8,%rdx,1),%r8d
   9a817:	cmp    %rax,%rcx
   9a81a:	mov    %r8b,0x8(%rsi,%r11,1)
   9a81f:	jae    99dac <__strxfrm_l+0x57c>
   9a825:	lea    (%rbx,%rcx,1),%r8
   9a829:	add    %r14,%rcx
   9a82c:	movzbl (%rcx,%rdx,1),%ecx
   9a830:	mov    %cl,(%r8,%rdi,1)
   9a834:	lea    0xa(%rsi),%rcx
   9a838:	cmp    %rax,%rcx
   9a83b:	jae    99dac <__strxfrm_l+0x57c>
   9a841:	lea    (%rbx,%rcx,1),%r8
   9a845:	add    %r14,%rcx
   9a848:	movzbl (%rcx,%rdx,1),%ecx
   9a84c:	mov    %cl,(%r8,%rdi,1)
   9a850:	lea    0xb(%rsi),%rcx
   9a854:	cmp    %rax,%rcx
   9a857:	jae    99dac <__strxfrm_l+0x57c>
   9a85d:	lea    (%rbx,%rcx,1),%r8
   9a861:	add    %r14,%rcx
   9a864:	movzbl (%rcx,%rdx,1),%ecx
   9a868:	mov    %cl,(%r8,%rdi,1)
   9a86c:	lea    0xc(%rsi),%rcx
   9a870:	cmp    %rax,%rcx
   9a873:	jae    99dac <__strxfrm_l+0x57c>
   9a879:	lea    (%rbx,%rcx,1),%r8
   9a87d:	add    %r14,%rcx
   9a880:	movzbl (%rcx,%rdx,1),%ecx
   9a884:	mov    %cl,(%r8,%rdi,1)
   9a888:	lea    0xd(%rsi),%rcx
   9a88c:	cmp    %rax,%rcx
   9a88f:	jae    99dac <__strxfrm_l+0x57c>
   9a895:	lea    (%rbx,%rcx,1),%r8
   9a899:	add    %r14,%rcx
   9a89c:	add    $0xe,%rsi
   9a8a0:	movzbl (%rcx,%rdx,1),%ecx
   9a8a4:	cmp    %rax,%rsi
   9a8a7:	mov    %cl,(%r8,%rdi,1)
   9a8ab:	jae    99dac <__strxfrm_l+0x57c>
   9a8b1:	lea    (%rbx,%rsi,1),%rcx
   9a8b5:	add    %r14,%rsi
   9a8b8:	movzbl (%rsi,%rdx,1),%edx
   9a8bc:	mov    %dl,(%rcx,%rdi,1)
   9a8bf:	jmpq   99dac <__strxfrm_l+0x57c>
   9a8c4:	test   %r13,%r13
   9a8c7:	cmove  %rbx,%r13
   9a8cb:	addq   $0x1,-0x50(%rbp)
   9a8d0:	jmpq   99e2c <__strxfrm_l+0x5fc>
   9a8d5:	xor    %ecx,%ecx
   9a8d7:	add    -0xa8(%rbp),%rcx
   9a8de:	jmpq   99cbe <__strxfrm_l+0x48e>
   9a8e3:	xor    %edx,%edx
   9a8e5:	movzbl (%r8,%rdx,1),%ecx
   9a8ea:	mov    %cl,(%r11,%rdx,1)
   9a8ee:	add    $0x1,%rdx
   9a8f2:	cmp    %rdx,%rax
   9a8f5:	jne    9a8e5 <__strxfrm_l+0x10b5>
   9a8f7:	jmpq   99dac <__strxfrm_l+0x57c>
   9a8fc:	mov    -0x70(%rbp),%rdx
   9a900:	sub    %rax,%rdx
   9a903:	movslq (%rdx),%r9
   9a906:	lea    0x5(%rdx),%rcx
   9a90a:	movzbl 0x4(%rdx),%eax
   9a90e:	test   %r9d,%r9d
   9a911:	js     9a97d <__strxfrm_l+0x114d>
   9a913:	test   %rax,%rax
   9a916:	je     9d35f <__strxfrm_l+0x3b2f>
   9a91c:	movzbl 0x1(%rbx),%edi
   9a920:	cmp    %dil,0x5(%rdx)
   9a924:	jne    9a950 <__strxfrm_l+0x1120>
   9a926:	xor    %edx,%edx
   9a928:	jmp    9a93b <__strxfrm_l+0x110b>
   9a92a:	nopw   0x0(%rax,%rax,1)
   9a930:	movzbl 0x1(%rbx,%rdx,1),%edi
   9a935:	cmp    %dil,(%rcx,%rdx,1)
   9a939:	jne    9a950 <__strxfrm_l+0x1120>
   9a93b:	add    $0x1,%rdx
   9a93f:	cmp    %rdx,%rax
   9a942:	jne    9a930 <__strxfrm_l+0x1100>
   9a944:	add    %rdx,-0xc0(%rbp)
   9a94b:	jmpq   99c09 <__strxfrm_l+0x3d9>
   9a950:	lea    (%rcx,%rax,1),%rdx
   9a954:	add    $0x1,%rax
   9a958:	mov    $0x4,%ecx
   9a95d:	and    $0x3,%eax
   9a960:	sub    %rax,%rcx
   9a963:	add    %rdx,%rcx
   9a966:	test   %rax,%rax
   9a969:	cmovne %rcx,%rdx
   9a96d:	movslq (%rdx),%r9
   9a970:	lea    0x5(%rdx),%rcx
   9a974:	movzbl 0x4(%rdx),%eax
   9a978:	test   %r9d,%r9d
   9a97b:	jns    9a913 <__strxfrm_l+0x10e3>
   9a97d:	test   %rax,%rax
   9a980:	je     9d415 <__strxfrm_l+0x3be5>
   9a986:	movzbl 0x1(%rbx),%r8d
   9a98b:	movzbl 0x5(%rdx),%r11d
   9a990:	cmp    %r8b,%r11b
   9a993:	mov    %r8b,-0x88(%rbp)
   9a99a:	jne    9a9d0 <__strxfrm_l+0x11a0>
   9a99c:	xor    %edx,%edx
   9a99e:	jmp    9a9ae <__strxfrm_l+0x117e>
   9a9a0:	movzbl (%rcx,%rdx,1),%edi
   9a9a4:	movzbl 0x1(%rbx,%rdx,1),%esi
   9a9a9:	cmp    %sil,%dil
   9a9ac:	jne    9a9d6 <__strxfrm_l+0x11a6>
   9a9ae:	add    $0x1,%rdx
   9a9b2:	cmp    %rdx,%rax
   9a9b5:	jne    9a9a0 <__strxfrm_l+0x1170>
   9a9b7:	xor    %esi,%esi
   9a9b9:	mov    -0x78(%rbp),%rax
   9a9bd:	sub    %r9,%rsi
   9a9c0:	add    %rdx,-0xc0(%rbp)
   9a9c7:	mov    (%rax,%rsi,4),%r9d
   9a9cb:	jmpq   99c09 <__strxfrm_l+0x3d9>
   9a9d0:	mov    %r11d,%edi
   9a9d3:	mov    %r8d,%esi
   9a9d6:	cmp    %sil,%dil
   9a9d9:	ja     9aa59 <__strxfrm_l+0x1229>
   9a9db:	lea    (%rcx,%rax,1),%rsi
   9a9df:	movzbl (%rsi),%r10d
   9a9e3:	cmp    %r8b,%r10b
   9a9e6:	jne    9aa51 <__strxfrm_l+0x1221>
   9a9e8:	xor    %edx,%edx
   9a9ea:	jmp    9a9fb <__strxfrm_l+0x11cb>
   9a9ec:	movzbl (%rsi,%rdx,1),%edi
   9a9f0:	movzbl 0x1(%rbx,%rdx,1),%r8d
   9a9f6:	cmp    %r8b,%dil
   9a9f9:	jne    9aa54 <__strxfrm_l+0x1224>
   9a9fb:	add    $0x1,%rdx
   9a9ff:	cmp    %rdx,%rax
   9aa02:	jne    9a9ec <__strxfrm_l+0x11bc>
   9aa04:	mov    %r10b,-0x88(%rbp)
   9aa0b:	xor    %r8d,%r8d
   9aa0e:	cmp    -0x88(%rbp),%r11b
   9aa15:	jne    9aa27 <__strxfrm_l+0x11f7>
   9aa17:	add    $0x1,%r8
   9aa1b:	movzbl 0x1(%rbx,%r8,1),%edi
   9aa21:	cmp    %dil,(%rcx,%r8,1)
   9aa25:	je     9aa17 <__strxfrm_l+0x11e7>
   9aa27:	xor    %esi,%esi
   9aa29:	movzbl 0x1(%rbx,%r8,1),%edx
   9aa2f:	movzbl (%rcx,%r8,1),%edi
   9aa34:	shl    $0x8,%rsi
   9aa38:	add    $0x1,%r8
   9aa3c:	sub    %edi,%edx
   9aa3e:	movslq %edx,%rdx
   9aa41:	add    %rdx,%rsi
   9aa44:	cmp    %rax,%r8
   9aa47:	jb     9aa29 <__strxfrm_l+0x11f9>
   9aa49:	mov    %rax,%rdx
   9aa4c:	jmpq   9a9b9 <__strxfrm_l+0x1189>
   9aa51:	mov    %r10d,%edi
   9aa54:	cmp    %r8b,%dil
   9aa57:	jae    9aa0b <__strxfrm_l+0x11db>
   9aa59:	add    %rax,%rax
   9aa5c:	lea    0x4(%rax),%rdx
   9aa60:	add    $0x1,%rax
   9aa64:	and    $0x3,%eax
   9aa67:	sub    %rax,%rdx
   9aa6a:	add    %rcx,%rdx
   9aa6d:	jmpq   9a903 <__strxfrm_l+0x10d3>
   9aa72:	mov    -0x60(%rbp),%eax
   9aa75:	test   $0xfffff800,%eax
   9aa7a:	je     9d440 <__strxfrm_l+0x3c10>
   9aa80:	test   $0xffff0000,%eax
   9aa85:	je     9d591 <__strxfrm_l+0x3d61>
   9aa8b:	test   $0xffe00000,%eax
   9aa90:	je     9d57d <__strxfrm_l+0x3d4d>
   9aa96:	and    $0xfc000000,%eax
   9aa9b:	cmp    $0x1,%eax
   9aa9e:	sbb    %rdi,%rdi
   9aaa1:	add    $0x6,%rdi
   9aaa5:	cmp    $0x1,%eax
   9aaa8:	sbb    %edx,%edx
   9aaaa:	add    $0x5,%edx
   9aaad:	cmp    $0x1,%eax
   9aab0:	sbb    %eax,%eax
   9aab2:	and    $0xfffffffc,%eax
   9aab5:	sub    $0x4,%eax
   9aab8:	mov    -0x60(%rbp),%ebx
   9aabb:	mov    %al,-0x40(%rbp)
   9aabe:	movslq %edx,%rcx
   9aac1:	mov    %ebx,%eax
   9aac3:	and    $0x3f,%eax
   9aac6:	or     $0xffffff80,%eax
   9aac9:	mov    %al,-0x40(%rbp,%rcx,1)
   9aacd:	lea    -0x1(%rdx),%eax
   9aad0:	movslq %eax,%rcx
   9aad3:	mov    %ebx,%eax
   9aad5:	sar    $0x6,%eax
   9aad8:	and    $0x3f,%eax
   9aadb:	or     $0xffffff80,%eax
   9aade:	mov    %al,-0x40(%rbp,%rcx,1)
   9aae2:	mov    %ebx,%eax
   9aae4:	mov    %edx,%ecx
   9aae6:	sar    $0xc,%eax
   9aae9:	sub    $0x2,%ecx
   9aaec:	je     9ab2c <__strxfrm_l+0x12fc>
   9aaee:	and    $0x3f,%eax
   9aaf1:	movslq %ecx,%rcx
   9aaf4:	or     $0xffffff80,%eax
   9aaf7:	mov    %al,-0x40(%rbp,%rcx,1)
   9aafb:	mov    %ebx,%eax
   9aafd:	mov    %edx,%ecx
   9aaff:	sar    $0x12,%eax
   9ab02:	sub    $0x3,%ecx
   9ab05:	je     9ab2c <__strxfrm_l+0x12fc>
   9ab07:	and    $0x3f,%eax
   9ab0a:	movslq %ecx,%rcx
   9ab0d:	or     $0xffffff80,%eax
   9ab10:	mov    %al,-0x40(%rbp,%rcx,1)
   9ab14:	mov    %ebx,%eax
   9ab16:	sar    $0x18,%eax
   9ab19:	cmp    $0x4,%edx
   9ab1c:	je     9ab2c <__strxfrm_l+0x12fc>
   9ab1e:	and    $0x3f,%eax
   9ab21:	or     $0xffffff80,%eax
   9ab24:	mov    %al,-0x3f(%rbp)
   9ab27:	mov    %ebx,%eax
   9ab29:	sar    $0x1e,%eax
   9ab2c:	mov    %eax,%edx
   9ab2e:	mov    -0x58(%rbp),%rax
   9ab32:	or     -0x40(%rbp),%dl
   9ab35:	lea    (%rax,%rdi,1),%rcx
   9ab39:	mov    -0x88(%rbp),%rax
   9ab40:	mov    %dl,-0x40(%rbp)
   9ab43:	add    %rcx,%rax
   9ab46:	cmp    %rax,-0x68(%rbp)
   9ab4a:	jbe    99e10 <__strxfrm_l+0x5e0>
   9ab50:	movzbl -0x3f(%rbp),%eax
   9ab54:	mov    -0x58(%rbp),%rbx
   9ab58:	cmp    $0x2,%rdi
   9ab5c:	mov    %dl,(%r12,%rbx,1)
   9ab60:	mov    %al,0x1(%r12,%rbx,1)
   9ab65:	je     9aba2 <__strxfrm_l+0x1372>
   9ab67:	movzbl -0x3e(%rbp),%eax
   9ab6b:	cmp    $0x3,%rdi
   9ab6f:	mov    %al,0x2(%r12,%rbx,1)
   9ab74:	je     9aba2 <__strxfrm_l+0x1372>
   9ab76:	movzbl -0x3d(%rbp),%eax
   9ab7a:	cmp    $0x4,%rdi
   9ab7e:	mov    %al,0x3(%r12,%rbx,1)
   9ab83:	je     9aba2 <__strxfrm_l+0x1372>
   9ab85:	movzbl -0x3c(%rbp),%eax
   9ab89:	cmp    $0x5,%rdi
   9ab8d:	mov    %al,0x4(%r12,%rbx,1)
   9ab92:	je     9aba2 <__strxfrm_l+0x1372>
   9ab94:	movzbl -0x3b(%rbp),%eax
   9ab98:	mov    $0x6,%edi
   9ab9d:	mov    %al,0x5(%r12,%rbx,1)
   9aba2:	movslq -0xd0(%rbp),%rsi
   9aba9:	lea    (%r12,%rcx,1),%r10
   9abad:	lea    0x10(%r14,%rsi,1),%rax
   9abb2:	lea    (%r14,%rsi,1),%r8
   9abb6:	cmp    %rax,%r10
   9abb9:	lea    0x10(%r12,%rcx,1),%rax
   9abbe:	setae  %dl
   9abc1:	cmp    %rax,%r8
   9abc4:	setae  %al
   9abc7:	or     %al,%dl
   9abc9:	je     9d423 <__strxfrm_l+0x3bf3>
   9abcf:	cmpq   $0x14,-0x88(%rbp)
   9abd7:	jbe    9d423 <__strxfrm_l+0x3bf3>
   9abdd:	mov    %r8,%rax
   9abe0:	xor    %edx,%edx
   9abe2:	neg    %rax
   9abe5:	and    $0xf,%eax
   9abe8:	je     9ad20 <__strxfrm_l+0x14f0>
   9abee:	movzbl (%r8),%edx
   9abf2:	cmp    $0x1,%rax
   9abf6:	mov    %dl,(%r10)
   9abf9:	je     9d627 <__strxfrm_l+0x3df7>
   9abff:	movzbl 0x1(%r14,%rsi,1),%edx
   9ac05:	cmp    $0x2,%rax
   9ac09:	mov    %dl,0x1(%r12,%rcx,1)
   9ac0e:	je     9d61d <__strxfrm_l+0x3ded>
   9ac14:	movzbl 0x2(%r14,%rsi,1),%edx
   9ac1a:	cmp    $0x3,%rax
   9ac1e:	mov    %dl,0x2(%r12,%rcx,1)
   9ac23:	je     9d613 <__strxfrm_l+0x3de3>
   9ac29:	movzbl 0x3(%r14,%rsi,1),%edx
   9ac2f:	cmp    $0x4,%rax
   9ac33:	mov    %dl,0x3(%r12,%rcx,1)
   9ac38:	je     9d609 <__strxfrm_l+0x3dd9>
   9ac3e:	movzbl 0x4(%r14,%rsi,1),%edx
   9ac44:	cmp    $0x5,%rax
   9ac48:	mov    %dl,0x4(%r12,%rcx,1)
   9ac4d:	je     9d5ff <__strxfrm_l+0x3dcf>
   9ac53:	movzbl 0x5(%r14,%rsi,1),%edx
   9ac59:	cmp    $0x6,%rax
   9ac5d:	mov    %dl,0x5(%r12,%rcx,1)
   9ac62:	je     9d5f5 <__strxfrm_l+0x3dc5>
   9ac68:	movzbl 0x6(%r14,%rsi,1),%edx
   9ac6e:	cmp    $0x7,%rax
   9ac72:	mov    %dl,0x6(%r12,%rcx,1)
   9ac77:	je     9d5eb <__strxfrm_l+0x3dbb>
   9ac7d:	movzbl 0x7(%r14,%rsi,1),%edx
   9ac83:	cmp    $0x8,%rax
   9ac87:	mov    %dl,0x7(%r12,%rcx,1)
   9ac8c:	je     9d5e1 <__strxfrm_l+0x3db1>
   9ac92:	movzbl 0x8(%r14,%rsi,1),%edx
   9ac98:	cmp    $0x9,%rax
   9ac9c:	mov    %dl,0x8(%r12,%rcx,1)
   9aca1:	je     9d5d7 <__strxfrm_l+0x3da7>
   9aca7:	movzbl 0x9(%r14,%rsi,1),%edx
   9acad:	cmp    $0xa,%rax
   9acb1:	mov    %dl,0x9(%r12,%rcx,1)
   9acb6:	je     9d5cd <__strxfrm_l+0x3d9d>
   9acbc:	movzbl 0xa(%r14,%rsi,1),%edx
   9acc2:	cmp    $0xb,%rax
   9acc6:	mov    %dl,0xa(%r12,%rcx,1)
   9accb:	je     9d5c3 <__strxfrm_l+0x3d93>
   9acd1:	movzbl 0xb(%r14,%rsi,1),%edx
   9acd7:	cmp    $0xc,%rax
   9acdb:	mov    %dl,0xb(%r12,%rcx,1)
   9ace0:	je     9d5b9 <__strxfrm_l+0x3d89>
   9ace6:	movzbl 0xc(%r14,%rsi,1),%edx
   9acec:	cmp    $0xd,%rax
   9acf0:	mov    %dl,0xc(%r12,%rcx,1)
   9acf5:	je     9d5af <__strxfrm_l+0x3d7f>
   9acfb:	movzbl 0xd(%r14,%rsi,1),%edx
   9ad01:	cmp    $0xf,%rax
   9ad05:	mov    %dl,0xd(%r12,%rcx,1)
   9ad0a:	jne    9d5a5 <__strxfrm_l+0x3d75>
   9ad10:	movzbl 0xe(%r14,%rsi,1),%edx
   9ad16:	mov    %dl,0xe(%r12,%rcx,1)
   9ad1b:	mov    $0xf,%edx
   9ad20:	mov    -0x88(%rbp),%r9
   9ad27:	mov    %r9,%r11
   9ad2a:	sub    $0x1,%r9
   9ad2e:	sub    %rax,%r11
   9ad31:	sub    %rax,%r9
   9ad34:	lea    -0x10(%r11),%r8
   9ad38:	shr    $0x4,%r8
   9ad3c:	add    $0x1,%r8
   9ad40:	mov    %r8,%rbx
   9ad43:	shl    $0x4,%rbx
   9ad47:	cmp    $0xe,%r9
   9ad4b:	jbe    9aeb6 <__strxfrm_l+0x1686>
   9ad51:	lea    (%rax,%rsi,1),%r9
   9ad55:	add    %rcx,%rax
   9ad58:	add    %r12,%rax
   9ad5b:	add    %r14,%r9
   9ad5e:	cmp    $0x1,%r8
   9ad62:	movdqa (%r9),%xmm0
   9ad67:	movups %xmm0,(%rax)
   9ad6a:	je     9aeaa <__strxfrm_l+0x167a>
   9ad70:	cmp    $0x2,%r8
   9ad74:	movdqa 0x10(%r9),%xmm0
   9ad7a:	movups %xmm0,0x10(%rax)
   9ad7e:	je     9aeaa <__strxfrm_l+0x167a>
   9ad84:	cmp    $0x3,%r8
   9ad88:	movdqa 0x20(%r9),%xmm0
   9ad8e:	movups %xmm0,0x20(%rax)
   9ad92:	je     9aeaa <__strxfrm_l+0x167a>
   9ad98:	cmp    $0x4,%r8
   9ad9c:	movdqa 0x30(%r9),%xmm0
   9ada2:	movups %xmm0,0x30(%rax)
   9ada6:	je     9aeaa <__strxfrm_l+0x167a>
   9adac:	cmp    $0x5,%r8
   9adb0:	movdqa 0x40(%r9),%xmm0
   9adb6:	movups %xmm0,0x40(%rax)
   9adba:	je     9aeaa <__strxfrm_l+0x167a>
   9adc0:	cmp    $0x6,%r8
   9adc4:	movdqa 0x50(%r9),%xmm0
   9adca:	movups %xmm0,0x50(%rax)
   9adce:	je     9aeaa <__strxfrm_l+0x167a>
   9add4:	cmp    $0x7,%r8
   9add8:	movdqa 0x60(%r9),%xmm0
   9adde:	movups %xmm0,0x60(%rax)
   9ade2:	je     9aeaa <__strxfrm_l+0x167a>
   9ade8:	cmp    $0x8,%r8
   9adec:	movdqa 0x70(%r9),%xmm0
   9adf2:	movups %xmm0,0x70(%rax)
   9adf6:	je     9aeaa <__strxfrm_l+0x167a>
   9adfc:	cmp    $0x9,%r8
   9ae00:	movdqa 0x80(%r9),%xmm0
   9ae09:	movups %xmm0,0x80(%rax)
   9ae10:	je     9aeaa <__strxfrm_l+0x167a>
   9ae16:	cmp    $0xa,%r8
   9ae1a:	movdqa 0x90(%r9),%xmm0
   9ae23:	movups %xmm0,0x90(%rax)
   9ae2a:	je     9aeaa <__strxfrm_l+0x167a>
   9ae2c:	cmp    $0xb,%r8
   9ae30:	movdqa 0xa0(%r9),%xmm0
   9ae39:	movups %xmm0,0xa0(%rax)
   9ae40:	je     9aeaa <__strxfrm_l+0x167a>
   9ae42:	cmp    $0xc,%r8
   9ae46:	movdqa 0xb0(%r9),%xmm0
   9ae4f:	movups %xmm0,0xb0(%rax)
   9ae56:	je     9aeaa <__strxfrm_l+0x167a>
   9ae58:	cmp    $0xd,%r8
   9ae5c:	movdqa 0xc0(%r9),%xmm0
   9ae65:	movups %xmm0,0xc0(%rax)
   9ae6c:	je     9aeaa <__strxfrm_l+0x167a>
   9ae6e:	cmp    $0xe,%r8
   9ae72:	movdqa 0xd0(%r9),%xmm0
   9ae7b:	movups %xmm0,0xd0(%rax)
   9ae82:	je     9aeaa <__strxfrm_l+0x167a>
   9ae84:	cmp    $0xf,%r8
   9ae88:	movdqa 0xe0(%r9),%xmm0
   9ae91:	movups %xmm0,0xe0(%rax)
   9ae98:	je     9aeaa <__strxfrm_l+0x167a>
   9ae9a:	movdqa 0xf0(%r9),%xmm0
   9aea3:	movups %xmm0,0xf0(%rax)
   9aeaa:	add    %rbx,%rdx
   9aead:	cmp    %r11,%rbx
   9aeb0:	je     99e10 <__strxfrm_l+0x5e0>
   9aeb6:	lea    (%r14,%rdx,1),%rax
   9aeba:	mov    -0x88(%rbp),%rbx
   9aec1:	movzbl (%rax,%rsi,1),%eax
   9aec5:	mov    %al,(%r10,%rdx,1)
   9aec9:	lea    0x1(%rdx),%rax
   9aecd:	cmp    %rbx,%rax
   9aed0:	jae    99e10 <__strxfrm_l+0x5e0>
   9aed6:	lea    (%r12,%rax,1),%r8
   9aeda:	add    %r14,%rax
   9aedd:	movzbl (%rax,%rsi,1),%eax
   9aee1:	mov    %al,(%r8,%rcx,1)
   9aee5:	lea    0x2(%rdx),%rax
   9aee9:	cmp    %rbx,%rax
   9aeec:	jae    99e10 <__strxfrm_l+0x5e0>
   9aef2:	lea    (%r12,%rax,1),%r8
   9aef6:	add    %r14,%rax
   9aef9:	movzbl (%rax,%rsi,1),%eax
   9aefd:	mov    %al,(%r8,%rcx,1)
   9af01:	lea    0x3(%rdx),%rax
   9af05:	cmp    %rbx,%rax
   9af08:	jae    99e10 <__strxfrm_l+0x5e0>
   9af0e:	lea    (%r12,%rax,1),%r8
   9af12:	add    %r14,%rax
   9af15:	movzbl (%rax,%rsi,1),%eax
   9af19:	mov    %al,(%r8,%rcx,1)
   9af1d:	lea    0x4(%rdx),%rax
   9af21:	cmp    %rbx,%rax
   9af24:	jae    99e10 <__strxfrm_l+0x5e0>
   9af2a:	lea    (%r12,%rax,1),%r8
   9af2e:	add    %r14,%rax
   9af31:	movzbl (%rax,%rsi,1),%eax
   9af35:	mov    %al,(%r8,%rcx,1)
   9af39:	lea    0x5(%rdx),%rax
   9af3d:	cmp    %rbx,%rax
   9af40:	jae    99e10 <__strxfrm_l+0x5e0>
   9af46:	lea    (%r12,%rax,1),%r8
   9af4a:	add    %r14,%rax
   9af4d:	movzbl (%rax,%rsi,1),%eax
   9af51:	mov    %al,(%r8,%rcx,1)
   9af55:	lea    0x6(%rdx),%rax
   9af59:	cmp    %rbx,%rax
   9af5c:	jae    99e10 <__strxfrm_l+0x5e0>
   9af62:	lea    (%r12,%rax,1),%r8
   9af66:	add    %r14,%rax
   9af69:	movzbl (%rax,%rsi,1),%eax
   9af6d:	mov    %al,(%r8,%rcx,1)
   9af71:	lea    0x7(%rdx),%rax
   9af75:	cmp    %rbx,%rax
   9af78:	jae    99e10 <__strxfrm_l+0x5e0>
   9af7e:	lea    (%r12,%rax,1),%r8
   9af82:	add    %r14,%rax
   9af85:	movzbl (%rax,%rsi,1),%eax
   9af89:	mov    %al,(%r8,%rcx,1)
   9af8d:	lea    0x8(%rdx),%rax
   9af91:	cmp    %rbx,%rax
   9af94:	jae    99e10 <__strxfrm_l+0x5e0>
   9af9a:	lea    (%r12,%rax,1),%r8
   9af9e:	add    %r14,%rax
   9afa1:	movzbl (%rax,%rsi,1),%eax
   9afa5:	mov    %al,(%r8,%rcx,1)
   9afa9:	lea    0x9(%rdx),%rax
   9afad:	cmp    %rbx,%rax
   9afb0:	jae    99e10 <__strxfrm_l+0x5e0>
   9afb6:	lea    (%r12,%rax,1),%r8
   9afba:	add    %r14,%rax
   9afbd:	movzbl (%rax,%rsi,1),%eax
   9afc1:	mov    %al,(%r8,%rcx,1)
   9afc5:	lea    0xa(%rdx),%rax
   9afc9:	cmp    %rbx,%rax
   9afcc:	jae    99e10 <__strxfrm_l+0x5e0>
   9afd2:	lea    (%r12,%rax,1),%r8
   9afd6:	add    %r14,%rax
   9afd9:	movzbl (%rax,%rsi,1),%eax
   9afdd:	mov    %al,(%r8,%rcx,1)
   9afe1:	lea    0xb(%rdx),%rax
   9afe5:	cmp    %rbx,%rax
   9afe8:	jae    99e10 <__strxfrm_l+0x5e0>
   9afee:	lea    (%r12,%rax,1),%r8
   9aff2:	add    %r14,%rax
   9aff5:	movzbl (%rax,%rsi,1),%eax
   9aff9:	mov    %al,(%r8,%rcx,1)
   9affd:	lea    0xc(%rdx),%rax
   9b001:	cmp    %rbx,%rax
   9b004:	jae    99e10 <__strxfrm_l+0x5e0>
   9b00a:	lea    (%r12,%rax,1),%r8
   9b00e:	add    %r14,%rax
   9b011:	movzbl (%rax,%rsi,1),%eax
   9b015:	mov    %al,(%r8,%rcx,1)
   9b019:	lea    0xd(%rdx),%rax
   9b01d:	cmp    %rbx,%rax
   9b020:	jae    99e10 <__strxfrm_l+0x5e0>
   9b026:	lea    (%r12,%rax,1),%r8
   9b02a:	add    %r14,%rax
   9b02d:	add    $0xe,%rdx
   9b031:	movzbl (%rax,%rsi,1),%eax
   9b035:	cmp    %rbx,%rdx
   9b038:	mov    %al,(%r8,%rcx,1)
   9b03c:	jae    99e10 <__strxfrm_l+0x5e0>
   9b042:	lea    (%r12,%rdx,1),%rax
   9b046:	add    %r14,%rdx
   9b049:	movzbl (%rdx,%rsi,1),%edx
   9b04d:	mov    %dl,(%rax,%rcx,1)
   9b050:	jmpq   99e10 <__strxfrm_l+0x5e0>
   9b055:	addl   $0x1,-0x60(%rbp)
   9b059:	xor    %r13d,%r13d
   9b05c:	jmpq   99e2c <__strxfrm_l+0x5fc>
   9b061:	movzbl -0x60(%rbp),%ecx
   9b065:	mov    -0x98(%rbp),%rbx
   9b06c:	mov    $0x1,%r9d
   9b072:	mov    -0x58(%rbp),%rsi
   9b076:	mov    %cl,(%rbx,%rsi,1)
   9b079:	jmpq   9a41f <__strxfrm_l+0xbef>
   9b07e:	mov    -0x70(%rbp),%rdx
   9b082:	sub    %rax,%rdx
   9b085:	movslq (%rdx),%rdi
   9b088:	lea    0x5(%rdx),%rsi
   9b08c:	movzbl 0x4(%rdx),%eax
   9b090:	test   %edi,%edi
   9b092:	js     9b0fc <__strxfrm_l+0x18cc>
   9b094:	test   %rax,%rax
   9b097:	je     9b1fe <__strxfrm_l+0x19ce>
   9b09d:	movzbl 0x1(%rcx),%r10d
   9b0a2:	cmp    %r10b,0x5(%rdx)
   9b0a6:	jne    9b0d0 <__strxfrm_l+0x18a0>
   9b0a8:	xor    %edx,%edx
   9b0aa:	jmp    9b0bc <__strxfrm_l+0x188c>
   9b0ac:	nopl   0x0(%rax)
   9b0b0:	movzbl 0x1(%rcx,%rdx,1),%r11d
   9b0b6:	cmp    %r11b,(%rsi,%rdx,1)
   9b0ba:	jne    9b0d0 <__strxfrm_l+0x18a0>
   9b0bc:	add    $0x1,%rdx
   9b0c0:	cmp    %rdx,%rax
   9b0c3:	jne    9b0b0 <__strxfrm_l+0x1880>
   9b0c5:	lea    0x0(%r13,%rdx,1),%rcx
   9b0ca:	jmpq   99eeb <__strxfrm_l+0x6bb>
   9b0cf:	nop
   9b0d0:	lea    (%rsi,%rax,1),%rdx
   9b0d4:	add    $0x1,%rax
   9b0d8:	mov    $0x4,%esi
   9b0dd:	and    $0x3,%eax
   9b0e0:	sub    %rax,%rsi
   9b0e3:	add    %rdx,%rsi
   9b0e6:	test   %rax,%rax
   9b0e9:	cmovne %rsi,%rdx
   9b0ed:	movslq (%rdx),%rdi
   9b0f0:	lea    0x5(%rdx),%rsi
   9b0f4:	movzbl 0x4(%rdx),%eax
   9b0f8:	test   %edi,%edi
   9b0fa:	jns    9b094 <__strxfrm_l+0x1864>
   9b0fc:	test   %rax,%rax
   9b0ff:	je     9b213 <__strxfrm_l+0x19e3>
   9b105:	movzbl 0x5(%rdx),%r12d
   9b10a:	movzbl 0x1(%rcx),%r11d
   9b10f:	cmp    %r12b,%r11b
   9b112:	jne    9b14f <__strxfrm_l+0x191f>
   9b114:	xor    %edx,%edx
   9b116:	jmp    9b130 <__strxfrm_l+0x1900>
   9b118:	nopl   0x0(%rax,%rax,1)
   9b120:	movzbl (%rsi,%rdx,1),%r9d
   9b125:	movzbl 0x1(%rcx,%rdx,1),%r8d
   9b12b:	cmp    %r8b,%r9b
   9b12e:	jne    9b155 <__strxfrm_l+0x1925>
   9b130:	add    $0x1,%rdx
   9b134:	cmp    %rdx,%rax
   9b137:	jne    9b120 <__strxfrm_l+0x18f0>
   9b139:	xor    %eax,%eax
   9b13b:	sub    %rdi,%rax
   9b13e:	mov    -0x78(%rbp),%rdi
   9b142:	lea    0x0(%r13,%rdx,1),%rcx
   9b147:	mov    (%rdi,%rax,4),%edi
   9b14a:	jmpq   99eeb <__strxfrm_l+0x6bb>
   9b14f:	mov    %r12d,%r9d
   9b152:	mov    %r11d,%r8d
   9b155:	cmp    %r8b,%r9b
   9b158:	ja     9b1d8 <__strxfrm_l+0x19a8>
   9b15a:	lea    (%rsi,%rax,1),%r10
   9b15e:	movzbl (%r10),%r8d
   9b162:	cmp    %r8b,%r11b
   9b165:	jne    9b1f1 <__strxfrm_l+0x19c1>
   9b16b:	xor    %edx,%edx
   9b16d:	jmp    9b180 <__strxfrm_l+0x1950>
   9b16f:	nop
   9b170:	movzbl (%r10,%rdx,1),%r8d
   9b175:	movzbl 0x1(%rcx,%rdx,1),%r9d
   9b17b:	cmp    %r9b,%r8b
   9b17e:	jne    9b1f4 <__strxfrm_l+0x19c4>
   9b180:	add    $0x1,%rdx
   9b184:	cmp    %rdx,%rax
   9b187:	jne    9b170 <__strxfrm_l+0x1940>
   9b189:	xor    %r8d,%r8d
   9b18c:	cmp    %r12b,%r11b
   9b18f:	jne    9b1a8 <__strxfrm_l+0x1978>
   9b191:	nopl   0x0(%rax)
   9b198:	add    $0x1,%r8
   9b19c:	movzbl 0x1(%rcx,%r8,1),%eax
   9b1a2:	cmp    %al,(%rsi,%r8,1)
   9b1a6:	je     9b198 <__strxfrm_l+0x1968>
   9b1a8:	xor    %eax,%eax
   9b1aa:	nopw   0x0(%rax,%rax,1)
   9b1b0:	shl    $0x8,%rax
   9b1b4:	movzbl (%rsi,%r8,1),%r9d
   9b1b9:	mov    %rax,%r10
   9b1bc:	movzbl 0x1(%rcx,%r8,1),%eax
   9b1c2:	add    $0x1,%r8
   9b1c6:	sub    %r9d,%eax
   9b1c9:	cltq   
   9b1cb:	add    %r10,%rax
   9b1ce:	cmp    %rdx,%r8
   9b1d1:	jb     9b1b0 <__strxfrm_l+0x1980>
   9b1d3:	jmpq   9b13b <__strxfrm_l+0x190b>
   9b1d8:	add    %rax,%rax
   9b1db:	lea    0x4(%rax),%rdx
   9b1df:	add    $0x1,%rax
   9b1e3:	and    $0x3,%eax
   9b1e6:	sub    %rax,%rdx
   9b1e9:	add    %rsi,%rdx
   9b1ec:	jmpq   9b085 <__strxfrm_l+0x1855>
   9b1f1:	mov    %r11d,%r9d
   9b1f4:	cmp    %r9b,%r8b
   9b1f7:	jb     9b1d8 <__strxfrm_l+0x19a8>
   9b1f9:	mov    %rax,%rdx
   9b1fc:	jmp    9b189 <__strxfrm_l+0x1959>
   9b1fe:	xor    %edx,%edx
   9b200:	lea    0x0(%r13,%rdx,1),%rcx
   9b205:	jmpq   99eeb <__strxfrm_l+0x6bb>
   9b20a:	addl   $0x1,-0x60(%rbp)
   9b20e:	jmpq   99f7d <__strxfrm_l+0x74d>
   9b213:	xor    %edx,%edx
   9b215:	jmpq   9b13b <__strxfrm_l+0x190b>
   9b21a:	mov    -0x70(%rbp),%rcx
   9b21e:	sub    %rax,%rcx
   9b221:	movslq (%rcx),%rsi
   9b224:	lea    0x5(%rcx),%rdx
   9b228:	movzbl 0x4(%rcx),%eax
   9b22c:	test   %esi,%esi
   9b22e:	js     9b2a4 <__strxfrm_l+0x1a74>
   9b230:	test   %rax,%rax
   9b233:	je     9b390 <__strxfrm_l+0x1b60>
   9b239:	movzbl 0x5(%rcx),%edi
   9b23d:	cmp    %dil,0x1(%r12)
   9b242:	jne    9b278 <__strxfrm_l+0x1a48>
   9b244:	xor    %ecx,%ecx
   9b246:	jmp    9b25c <__strxfrm_l+0x1a2c>
   9b248:	nopl   0x0(%rax,%rax,1)
   9b250:	movzbl 0x1(%r12,%rcx,1),%edi
   9b256:	cmp    %dil,(%rdx,%rcx,1)
   9b25a:	jne    9b278 <__strxfrm_l+0x1a48>
   9b25c:	add    $0x1,%rcx
   9b260:	cmp    %rcx,%rax
   9b263:	jne    9b250 <__strxfrm_l+0x1a20>
   9b265:	add    -0x88(%rbp),%rcx
   9b26c:	jmpq   99e87 <__strxfrm_l+0x657>
   9b271:	nopl   0x0(%rax)
   9b278:	lea    (%rdx,%rax,1),%rcx
   9b27c:	add    $0x1,%rax
   9b280:	mov    $0x4,%edx
   9b285:	and    $0x3,%eax
   9b288:	sub    %rax,%rdx
   9b28b:	add    %rcx,%rdx
   9b28e:	test   %rax,%rax
   9b291:	cmovne %rdx,%rcx
   9b295:	movslq (%rcx),%rsi
   9b298:	lea    0x5(%rcx),%rdx
   9b29c:	movzbl 0x4(%rcx),%eax
   9b2a0:	test   %esi,%esi
   9b2a2:	jns    9b230 <__strxfrm_l+0x1a00>
   9b2a4:	test   %rax,%rax
   9b2a7:	je     9d41c <__strxfrm_l+0x3bec>
   9b2ad:	movzbl 0x5(%rcx),%ebx
   9b2b1:	movzbl 0x1(%r12),%edi
   9b2b7:	cmp    %dil,%bl
   9b2ba:	jne    9b2f1 <__strxfrm_l+0x1ac1>
   9b2bc:	xor    %ecx,%ecx
   9b2be:	jmp    9b2d0 <__strxfrm_l+0x1aa0>
   9b2c0:	movzbl (%rdx,%rcx,1),%r9d
   9b2c5:	movzbl 0x1(%r12,%rcx,1),%r8d
   9b2cb:	cmp    %r8b,%r9b
   9b2ce:	jne    9b2f7 <__strxfrm_l+0x1ac7>
   9b2d0:	add    $0x1,%rcx
   9b2d4:	cmp    %rcx,%rax
   9b2d7:	jne    9b2c0 <__strxfrm_l+0x1a90>
   9b2d9:	xor    %eax,%eax
   9b2db:	mov    -0x78(%rbp),%rdi
   9b2df:	sub    %rsi,%rax
   9b2e2:	add    -0x88(%rbp),%rcx
   9b2e9:	mov    (%rdi,%rax,4),%esi
   9b2ec:	jmpq   99e87 <__strxfrm_l+0x657>
   9b2f1:	mov    %ebx,%r9d
   9b2f4:	mov    %edi,%r8d
   9b2f7:	cmp    %r8b,%r9b
   9b2fa:	ja     9b364 <__strxfrm_l+0x1b34>
   9b2fc:	lea    (%rdx,%rax,1),%r10
   9b300:	movzbl (%r10),%r11d
   9b304:	cmp    %dil,%r11b
   9b307:	jne    9b37d <__strxfrm_l+0x1b4d>
   9b309:	xor    %ecx,%ecx
   9b30b:	jmp    9b31d <__strxfrm_l+0x1aed>
   9b30d:	movzbl (%r10,%rcx,1),%r9d
   9b312:	movzbl 0x1(%r12,%rcx,1),%r8d
   9b318:	cmp    %r8b,%r9b
   9b31b:	jne    9b383 <__strxfrm_l+0x1b53>
   9b31d:	add    $0x1,%rcx
   9b321:	cmp    %rcx,%rax
   9b324:	jne    9b30d <__strxfrm_l+0x1add>
   9b326:	xor    %edi,%edi
   9b328:	cmp    %r11b,%bl
   9b32b:	jne    9b33c <__strxfrm_l+0x1b0c>
   9b32d:	add    $0x1,%rdi
   9b331:	movzbl 0x1(%r12,%rdi,1),%eax
   9b337:	cmp    %al,(%rdx,%rdi,1)
   9b33a:	je     9b32d <__strxfrm_l+0x1afd>
   9b33c:	xor    %eax,%eax
   9b33e:	movzbl 0x1(%r12,%rdi,1),%r8d
   9b344:	movzbl (%rdx,%rdi,1),%r9d
   9b349:	shl    $0x8,%rax
   9b34d:	add    $0x1,%rdi
   9b351:	sub    %r9d,%r8d
   9b354:	movslq %r8d,%r8
   9b357:	add    %r8,%rax
   9b35a:	cmp    %rcx,%rdi
   9b35d:	jb     9b33e <__strxfrm_l+0x1b0e>
   9b35f:	jmpq   9b2db <__strxfrm_l+0x1aab>
   9b364:	add    %rax,%rax
   9b367:	lea    0x4(%rax),%rcx
   9b36b:	add    $0x1,%rax
   9b36f:	and    $0x3,%eax
   9b372:	sub    %rax,%rcx
   9b375:	add    %rdx,%rcx
   9b378:	jmpq   9b221 <__strxfrm_l+0x19f1>
   9b37d:	mov    %edi,%r8d
   9b380:	mov    %r11d,%r9d
   9b383:	cmp    %r8b,%r9b
   9b386:	jb     9b364 <__strxfrm_l+0x1b34>
   9b388:	mov    %rax,%rcx
   9b38b:	mov    %edi,%r11d
   9b38e:	jmp    9b326 <__strxfrm_l+0x1af6>
   9b390:	xor    %ecx,%ecx
   9b392:	jmpq   9b265 <__strxfrm_l+0x1a35>
   9b397:	mov    -0x60(%rbp),%edi
   9b39a:	test   $0xfffff800,%edi
   9b3a0:	je     9d4d2 <__strxfrm_l+0x3ca2>
   9b3a6:	test   $0xffff0000,%edi
   9b3ac:	je     9d4bb <__strxfrm_l+0x3c8b>
   9b3b2:	test   $0xffe00000,%edi
   9b3b8:	je     9d476 <__strxfrm_l+0x3c46>
   9b3be:	and    $0xfc000000,%edi
   9b3c4:	mov    -0x60(%rbp),%ebx
   9b3c7:	cmp    $0x1,%edi
   9b3ca:	sbb    %r11,%r11
   9b3cd:	add    $0x6,%r11
   9b3d1:	cmp    $0x1,%edi
   9b3d4:	sbb    %esi,%esi
   9b3d6:	add    $0x5,%esi
   9b3d9:	cmp    $0x1,%edi
   9b3dc:	sbb    %ecx,%ecx
   9b3de:	and    $0xfffffffc,%ecx
   9b3e1:	sub    $0x4,%ecx
   9b3e4:	mov    %cl,-0x40(%rbp)
   9b3e7:	mov    %ebx,%ecx
   9b3e9:	movslq %esi,%rdi
   9b3ec:	and    $0x3f,%ecx
   9b3ef:	or     $0xffffff80,%ecx
   9b3f2:	mov    %cl,-0x40(%rbp,%rdi,1)
   9b3f6:	mov    %ebx,%ecx
   9b3f8:	lea    -0x1(%rsi),%edi
   9b3fb:	sar    $0x6,%ecx
   9b3fe:	and    $0x3f,%ecx
   9b401:	movslq %edi,%rdi
   9b404:	or     $0xffffff80,%ecx
   9b407:	mov    %cl,-0x40(%rbp,%rdi,1)
   9b40b:	mov    %ebx,%ecx
   9b40d:	mov    %esi,%edi
   9b40f:	sar    $0xc,%ecx
   9b412:	sub    $0x2,%edi
   9b415:	je     9b455 <__strxfrm_l+0x1c25>
   9b417:	and    $0x3f,%ecx
   9b41a:	movslq %edi,%rdi
   9b41d:	or     $0xffffff80,%ecx
   9b420:	mov    %cl,-0x40(%rbp,%rdi,1)
   9b424:	mov    %ebx,%ecx
   9b426:	mov    %esi,%edi
   9b428:	sar    $0x12,%ecx
   9b42b:	sub    $0x3,%edi
   9b42e:	je     9b455 <__strxfrm_l+0x1c25>
   9b430:	and    $0x3f,%ecx
   9b433:	movslq %edi,%rdi
   9b436:	or     $0xffffff80,%ecx
   9b439:	mov    %cl,-0x40(%rbp,%rdi,1)
   9b43d:	mov    %ebx,%ecx
   9b43f:	sar    $0x18,%ecx
   9b442:	cmp    $0x4,%esi
   9b445:	je     9b455 <__strxfrm_l+0x1c25>
   9b447:	and    $0x3f,%ecx
   9b44a:	or     $0xffffff80,%ecx
   9b44d:	mov    %cl,-0x3f(%rbp)
   9b450:	mov    %ebx,%ecx
   9b452:	sar    $0x1e,%ecx
   9b455:	mov    -0x58(%rbp),%rdi
   9b459:	or     -0x40(%rbp),%cl
   9b45c:	add    %r11,%rdi
   9b45f:	lea    (%rax,%rdi,1),%rsi
   9b463:	cmp    %rsi,-0x68(%rbp)
   9b467:	mov    %cl,-0x40(%rbp)
   9b46a:	jbe    99f6b <__strxfrm_l+0x73b>
   9b470:	mov    -0x58(%rbp),%rbx
   9b474:	cmp    $0x2,%r11
   9b478:	mov    %cl,0x0(%r13,%rbx,1)
   9b47d:	movzbl -0x3f(%rbp),%ecx
   9b481:	mov    %cl,0x1(%r13,%rbx,1)
   9b486:	je     9b4c4 <__strxfrm_l+0x1c94>
   9b488:	movzbl -0x3e(%rbp),%ecx
   9b48c:	cmp    $0x3,%r11
   9b490:	mov    %cl,0x2(%r13,%rbx,1)
   9b495:	je     9b4c4 <__strxfrm_l+0x1c94>
   9b497:	movzbl -0x3d(%rbp),%ecx
   9b49b:	cmp    $0x4,%r11
   9b49f:	mov    %cl,0x3(%r13,%rbx,1)
   9b4a4:	je     9b4c4 <__strxfrm_l+0x1c94>
   9b4a6:	movzbl -0x3c(%rbp),%ecx
   9b4aa:	cmp    $0x5,%r11
   9b4ae:	mov    %cl,0x4(%r13,%rbx,1)
   9b4b3:	je     9b4c4 <__strxfrm_l+0x1c94>
   9b4b5:	movzbl -0x3b(%rbp),%ecx
   9b4b9:	mov    $0x6,%r11d
   9b4bf:	mov    %cl,0x5(%r13,%rbx,1)
   9b4c4:	movslq %edx,%rdx
   9b4c7:	lea    0x10(%r13,%rdi,1),%rcx
   9b4cc:	lea    0x0(%r13,%rdi,1),%r9
   9b4d1:	lea    (%r14,%rdx,1),%rbx
   9b4d5:	cmp    %rcx,%rbx
   9b4d8:	lea    0x10(%r14,%rdx,1),%rcx
   9b4dd:	setae  %sil
   9b4e1:	cmp    %rcx,%r9
   9b4e4:	setae  %cl
   9b4e7:	or     %cl,%sil
   9b4ea:	je     9d45e <__strxfrm_l+0x3c2e>
   9b4f0:	cmp    $0x14,%rax
   9b4f4:	jbe    9d45e <__strxfrm_l+0x3c2e>
   9b4fa:	mov    %rbx,%rcx
   9b4fd:	xor    %esi,%esi
   9b4ff:	neg    %rcx
   9b502:	and    $0xf,%ecx
   9b505:	je     9b63c <__strxfrm_l+0x1e0c>
   9b50b:	movzbl (%rbx),%esi
   9b50e:	cmp    $0x1,%rcx
   9b512:	mov    %sil,(%r9)
   9b515:	je     9d573 <__strxfrm_l+0x3d43>
   9b51b:	movzbl 0x1(%r14,%rdx,1),%esi
   9b521:	cmp    $0x2,%rcx
   9b525:	mov    %sil,0x1(%r13,%rdi,1)
   9b52a:	je     9d569 <__strxfrm_l+0x3d39>
   9b530:	movzbl 0x2(%r14,%rdx,1),%esi
   9b536:	cmp    $0x3,%rcx
   9b53a:	mov    %sil,0x2(%r13,%rdi,1)
   9b53f:	je     9d55f <__strxfrm_l+0x3d2f>
   9b545:	movzbl 0x3(%r14,%rdx,1),%esi
   9b54b:	cmp    $0x4,%rcx
   9b54f:	mov    %sil,0x3(%r13,%rdi,1)
   9b554:	je     9d555 <__strxfrm_l+0x3d25>
   9b55a:	movzbl 0x4(%r14,%rdx,1),%esi
   9b560:	cmp    $0x5,%rcx
   9b564:	mov    %sil,0x4(%r13,%rdi,1)
   9b569:	je     9d54b <__strxfrm_l+0x3d1b>
   9b56f:	movzbl 0x5(%r14,%rdx,1),%esi
   9b575:	cmp    $0x6,%rcx
   9b579:	mov    %sil,0x5(%r13,%rdi,1)
   9b57e:	je     9d541 <__strxfrm_l+0x3d11>
   9b584:	movzbl 0x6(%r14,%rdx,1),%esi
   9b58a:	cmp    $0x7,%rcx
   9b58e:	mov    %sil,0x6(%r13,%rdi,1)
   9b593:	je     9d537 <__strxfrm_l+0x3d07>
   9b599:	movzbl 0x7(%r14,%rdx,1),%esi
   9b59f:	cmp    $0x8,%rcx
   9b5a3:	mov    %sil,0x7(%r13,%rdi,1)
   9b5a8:	je     9d52d <__strxfrm_l+0x3cfd>
   9b5ae:	movzbl 0x8(%r14,%rdx,1),%esi
   9b5b4:	cmp    $0x9,%rcx
   9b5b8:	mov    %sil,0x8(%r13,%rdi,1)
   9b5bd:	je     9d523 <__strxfrm_l+0x3cf3>
   9b5c3:	movzbl 0x9(%r14,%rdx,1),%esi
   9b5c9:	cmp    $0xa,%rcx
   9b5cd:	mov    %sil,0x9(%r13,%rdi,1)
   9b5d2:	je     9d519 <__strxfrm_l+0x3ce9>
   9b5d8:	movzbl 0xa(%r14,%rdx,1),%esi
   9b5de:	cmp    $0xb,%rcx
   9b5e2:	mov    %sil,0xa(%r13,%rdi,1)
   9b5e7:	je     9d50f <__strxfrm_l+0x3cdf>
   9b5ed:	movzbl 0xb(%r14,%rdx,1),%esi
   9b5f3:	cmp    $0xc,%rcx
   9b5f7:	mov    %sil,0xb(%r13,%rdi,1)
   9b5fc:	je     9d505 <__strxfrm_l+0x3cd5>
   9b602:	movzbl 0xc(%r14,%rdx,1),%esi
   9b608:	cmp    $0xd,%rcx
   9b60c:	mov    %sil,0xc(%r13,%rdi,1)
   9b611:	je     9d4fb <__strxfrm_l+0x3ccb>
   9b617:	movzbl 0xd(%r14,%rdx,1),%esi
   9b61d:	cmp    $0xf,%rcx
   9b621:	mov    %sil,0xd(%r13,%rdi,1)
   9b626:	jne    9d4f1 <__strxfrm_l+0x3cc1>
   9b62c:	movzbl 0xe(%r14,%rdx,1),%esi
   9b632:	mov    %sil,0xe(%r13,%rdi,1)
   9b637:	mov    $0xf,%esi
   9b63c:	mov    %rax,%r10
   9b63f:	sub    %rcx,%r10
   9b642:	lea    -0x10(%r10),%r8
   9b646:	mov    %r10,-0x60(%rbp)
   9b64a:	shr    $0x4,%r8
   9b64e:	add    $0x1,%r8
   9b652:	mov    %r8,%r10
   9b655:	shl    $0x4,%r10
   9b659:	mov    %r10,-0x98(%rbp)
   9b660:	lea    -0x1(%rax),%r10
   9b664:	sub    %rcx,%r10
   9b667:	cmp    $0xe,%r10
   9b66b:	jbe    9b7de <__strxfrm_l+0x1fae>
   9b671:	lea    (%rdx,%rcx,1),%r10
   9b675:	add    %rdi,%rcx
   9b678:	add    %r13,%rcx
   9b67b:	add    %r14,%r10
   9b67e:	cmp    $0x1,%r8
   9b682:	movdqa (%r10),%xmm0
   9b687:	movups %xmm0,(%rcx)
   9b68a:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b690:	cmp    $0x2,%r8
   9b694:	movdqa 0x10(%r10),%xmm0
   9b69a:	movups %xmm0,0x10(%rcx)
   9b69e:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b6a4:	cmp    $0x3,%r8
   9b6a8:	movdqa 0x20(%r10),%xmm0
   9b6ae:	movups %xmm0,0x20(%rcx)
   9b6b2:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b6b8:	cmp    $0x4,%r8
   9b6bc:	movdqa 0x30(%r10),%xmm0
   9b6c2:	movups %xmm0,0x30(%rcx)
   9b6c6:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b6cc:	cmp    $0x5,%r8
   9b6d0:	movdqa 0x40(%r10),%xmm0
   9b6d6:	movups %xmm0,0x40(%rcx)
   9b6da:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b6e0:	cmp    $0x6,%r8
   9b6e4:	movdqa 0x50(%r10),%xmm0
   9b6ea:	movups %xmm0,0x50(%rcx)
   9b6ee:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b6f4:	cmp    $0x7,%r8
   9b6f8:	movdqa 0x60(%r10),%xmm0
   9b6fe:	movups %xmm0,0x60(%rcx)
   9b702:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b708:	cmp    $0x8,%r8
   9b70c:	movdqa 0x70(%r10),%xmm0
   9b712:	movups %xmm0,0x70(%rcx)
   9b716:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b71c:	cmp    $0x9,%r8
   9b720:	movdqa 0x80(%r10),%xmm0
   9b729:	movups %xmm0,0x80(%rcx)
   9b730:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b736:	cmp    $0xa,%r8
   9b73a:	movdqa 0x90(%r10),%xmm0
   9b743:	movups %xmm0,0x90(%rcx)
   9b74a:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b74c:	cmp    $0xb,%r8
   9b750:	movdqa 0xa0(%r10),%xmm0
   9b759:	movups %xmm0,0xa0(%rcx)
   9b760:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b762:	cmp    $0xc,%r8
   9b766:	movdqa 0xb0(%r10),%xmm0
   9b76f:	movups %xmm0,0xb0(%rcx)
   9b776:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b778:	cmp    $0xd,%r8
   9b77c:	movdqa 0xc0(%r10),%xmm0
   9b785:	movups %xmm0,0xc0(%rcx)
   9b78c:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b78e:	cmp    $0xe,%r8
   9b792:	movdqa 0xd0(%r10),%xmm0
   9b79b:	movups %xmm0,0xd0(%rcx)
   9b7a2:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b7a4:	cmp    $0xf,%r8
   9b7a8:	movdqa 0xe0(%r10),%xmm0
   9b7b1:	movups %xmm0,0xe0(%rcx)
   9b7b8:	je     9b7ca <__strxfrm_l+0x1f9a>
   9b7ba:	movdqa 0xf0(%r10),%xmm0
   9b7c3:	movups %xmm0,0xf0(%rcx)
   9b7ca:	mov    -0x98(%rbp),%rdi
   9b7d1:	add    %rdi,%rsi
   9b7d4:	cmp    %rdi,-0x60(%rbp)
   9b7d8:	je     99f6b <__strxfrm_l+0x73b>
   9b7de:	movzbl (%rbx,%rsi,1),%ecx
   9b7e2:	mov    %cl,(%r9,%rsi,1)
   9b7e6:	lea    0x1(%rsi),%rcx
   9b7ea:	cmp    %rcx,%rax
   9b7ed:	jbe    99f6b <__strxfrm_l+0x73b>
   9b7f3:	lea    (%r14,%rcx,1),%rdi
   9b7f7:	lea    0x2(%rsi),%rcx
   9b7fb:	movzbl (%rdi,%rdx,1),%edi
   9b7ff:	cmp    %rcx,%rax
   9b802:	mov    %dil,0x1(%rsi,%r9,1)
   9b807:	jbe    99f6b <__strxfrm_l+0x73b>
   9b80d:	lea    (%r14,%rcx,1),%rdi
   9b811:	lea    0x3(%rsi),%rcx
   9b815:	movzbl (%rdi,%rdx,1),%edi
   9b819:	cmp    %rcx,%rax
   9b81c:	mov    %dil,0x2(%rsi,%r9,1)
   9b821:	jbe    99f6b <__strxfrm_l+0x73b>
   9b827:	lea    (%r14,%rcx,1),%rdi
   9b82b:	lea    0x4(%rsi),%rcx
   9b82f:	movzbl (%rdi,%rdx,1),%edi
   9b833:	cmp    %rcx,%rax
   9b836:	mov    %dil,0x3(%rsi,%r9,1)
   9b83b:	jbe    99f6b <__strxfrm_l+0x73b>
   9b841:	lea    (%r14,%rcx,1),%rdi
   9b845:	lea    0x5(%rsi),%rcx
   9b849:	movzbl (%rdi,%rdx,1),%edi
   9b84d:	cmp    %rcx,%rax
   9b850:	mov    %dil,0x4(%rsi,%r9,1)
   9b855:	jbe    99f6b <__strxfrm_l+0x73b>
   9b85b:	lea    (%r14,%rcx,1),%rdi
   9b85f:	lea    0x6(%rsi),%rcx
   9b863:	movzbl (%rdi,%rdx,1),%edi
   9b867:	cmp    %rax,%rcx
   9b86a:	mov    %dil,0x5(%rsi,%r9,1)
   9b86f:	jae    99f6b <__strxfrm_l+0x73b>
   9b875:	lea    (%r14,%rcx,1),%rdi
   9b879:	lea    0x7(%rsi),%rcx
   9b87d:	movzbl (%rdi,%rdx,1),%edi
   9b881:	cmp    %rax,%rcx
   9b884:	mov    %dil,0x6(%rsi,%r9,1)
   9b889:	jae    99f6b <__strxfrm_l+0x73b>
   9b88f:	lea    (%r14,%rcx,1),%rdi
   9b893:	lea    0x8(%rsi),%rcx
   9b897:	movzbl (%rdi,%rdx,1),%edi
   9b89b:	cmp    %rax,%rcx
   9b89e:	mov    %dil,0x7(%rsi,%r9,1)
   9b8a3:	jae    99f6b <__strxfrm_l+0x73b>
   9b8a9:	lea    (%r14,%rcx,1),%rdi
   9b8ad:	lea    0x9(%rsi),%rcx
   9b8b1:	movzbl (%rdi,%rdx,1),%edi
   9b8b5:	cmp    %rax,%rcx
   9b8b8:	mov    %dil,0x8(%rsi,%r9,1)
   9b8bd:	jae    99f6b <__strxfrm_l+0x73b>
   9b8c3:	lea    (%r14,%rcx,1),%rdi
   9b8c7:	lea    0xa(%rsi),%rcx
   9b8cb:	movzbl (%rdi,%rdx,1),%edi
   9b8cf:	cmp    %rax,%rcx
   9b8d2:	mov    %dil,0x9(%rsi,%r9,1)
   9b8d7:	jae    99f6b <__strxfrm_l+0x73b>
   9b8dd:	lea    (%r14,%rcx,1),%rdi
   9b8e1:	lea    0xb(%rsi),%rcx
   9b8e5:	movzbl (%rdi,%rdx,1),%edi
   9b8e9:	cmp    %rax,%rcx
   9b8ec:	mov    %dil,0xa(%rsi,%r9,1)
   9b8f1:	jae    99f6b <__strxfrm_l+0x73b>
   9b8f7:	lea    (%r14,%rcx,1),%rdi
   9b8fb:	lea    0xc(%rsi),%rcx
   9b8ff:	movzbl (%rdi,%rdx,1),%edi
   9b903:	cmp    %rax,%rcx
   9b906:	mov    %dil,0xb(%rsi,%r9,1)
   9b90b:	jae    99f6b <__strxfrm_l+0x73b>
   9b911:	lea    (%r14,%rcx,1),%rdi
   9b915:	lea    0xd(%rsi),%rcx
   9b919:	movzbl (%rdi,%rdx,1),%edi
   9b91d:	cmp    %rax,%rcx
   9b920:	mov    %dil,0xc(%rsi,%r9,1)
   9b925:	jae    99f6b <__strxfrm_l+0x73b>
   9b92b:	lea    (%r14,%rcx,1),%rdi
   9b92f:	add    $0xe,%rsi
   9b933:	movzbl (%rdi,%rdx,1),%edi
   9b937:	mov    %dil,-0x1(%rsi,%r9,1)
   9b93c:	cmp    %rax,%rsi
   9b93f:	jae    99f6b <__strxfrm_l+0x73b>
   9b945:	lea    (%r14,%rsi,1),%rcx
   9b949:	movzbl (%rcx,%rdx,1),%edx
   9b94d:	mov    %dl,(%r9,%rsi,1)
   9b951:	jmpq   99f6b <__strxfrm_l+0x73b>
   9b956:	mov    $0xe,%esi
   9b95b:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b960:	mov    $0xd,%esi
   9b965:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b96a:	mov    $0xc,%esi
   9b96f:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b974:	mov    $0xb,%esi
   9b979:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b97e:	mov    $0xa,%esi
   9b983:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b988:	mov    $0x9,%esi
   9b98d:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b992:	mov    $0x8,%esi
   9b997:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b99c:	mov    $0x7,%esi
   9b9a1:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b9a6:	mov    $0x6,%esi
   9b9ab:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b9b0:	mov    $0x5,%esi
   9b9b5:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b9ba:	mov    $0x4,%esi
   9b9bf:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b9c4:	mov    $0x3,%esi
   9b9c9:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b9ce:	mov    $0x2,%esi
   9b9d3:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b9d8:	mov    $0x1,%esi
   9b9dd:	jmpq   9a597 <__strxfrm_l+0xd67>
   9b9e2:	mov    -0xa0(%rbp),%rax
   9b9e9:	mov    %rdi,%rbx
   9b9ec:	mov    -0x80(%rbp),%rdi
   9b9f0:	lea    0x1(%rbx),%rcx
   9b9f4:	add    $0x1,%rax
   9b9f8:	cmp    %rax,%rdi
   9b9fb:	seta   0x0(%r13,%rbx,1)
   9ba01:	cmp    %rax,%rdi
   9ba04:	ja     99faf <__strxfrm_l+0x77f>
   9ba0a:	cmp    $0x2,%rcx
   9ba0e:	jbe    9e5e5 <__strxfrm_l+0x4db5>
   9ba14:	mov    -0xb0(%rbp),%rax
   9ba1b:	add    $0x1,%rax
   9ba1f:	cmp    %rcx,%rax
   9ba22:	jne    9e5e5 <__strxfrm_l+0x4db5>
   9ba28:	mov    -0x58(%rbp),%rdi
   9ba2c:	cmp    %rdi,-0x68(%rbp)
   9ba30:	jb     9f8e4 <__strxfrm_l+0x60b4>
   9ba36:	movb   $0x0,-0x1(%r13,%rdi,1)
   9ba3c:	lea    -0x1(%rdi),%r13
   9ba40:	jmpq   99895 <__strxfrm_l+0x65>
   9ba45:	nopl   (%rax)
   9ba48:	mov    -0xb0(%rbp),%rdi
   9ba4f:	xor    %r12d,%r12d
   9ba52:	movq   $0x0,-0x60(%rbp)
   9ba5a:	mov    %r15d,-0x98(%rbp)
   9ba61:	mov    %rdi,-0x58(%rbp)
   9ba65:	mov    -0xb8(%rbp),%rdi
   9ba6c:	add    -0xa0(%rbp),%rdi
   9ba73:	test   %al,%al
   9ba75:	mov    %rdi,-0xc0(%rbp)
   9ba7c:	je     9c724 <__strxfrm_l+0x2ef4>
   9ba82:	lea    0x1(%rbx),%rdi
   9ba86:	mov    %rdi,-0x88(%rbp)
   9ba8d:	mov    -0x48(%rbp),%rdi
   9ba91:	movslq (%rdi,%rax,4),%rax
   9ba95:	test   %rax,%rax
   9ba98:	mov    %rax,%rcx
   9ba9b:	js     9cf6f <__strxfrm_l+0x373f>
   9baa1:	mov    -0x98(%rbp),%edi
   9baa7:	mov    %ecx,%eax
   9baa9:	and    $0xffffff,%ecx
   9baaf:	shr    $0x18,%eax
   9bab2:	lea    0x1(%rcx),%r15d
   9bab6:	movslq %ecx,%rcx
   9bab9:	movzbl (%r14,%rcx,1),%r11d
   9babe:	test   %edi,%edi
   9bac0:	jle    9badd <__strxfrm_l+0x22ad>
   9bac2:	xor    %edx,%edx
   9bac4:	mov    %edi,%esi
   9bac6:	lea    (%r15,%r11,1),%ecx
   9baca:	add    $0x1,%edx
   9bacd:	cmp    %edx,%esi
   9bacf:	lea    0x1(%rcx),%r15d
   9bad3:	movslq %ecx,%rcx
   9bad6:	movzbl (%r14,%rcx,1),%r11d
   9badb:	jne    9bac6 <__strxfrm_l+0x2296>
   9badd:	movzbl %al,%eax
   9bae0:	mov    -0xc0(%rbp),%rdi
   9bae7:	imul   -0x80(%rbp),%rax
   9baec:	testb  $0x1,(%rdi,%rax,1)
   9baf0:	je     9cf30 <__strxfrm_l+0x3700>
   9baf6:	test   %r12,%r12
   9baf9:	je     9d356 <__strxfrm_l+0x3b26>
   9baff:	mov    -0x60(%rbp),%rax
   9bb03:	test   %rax,%rax
   9bb06:	mov    %rax,-0x50(%rbp)
   9bb0a:	je     9c1af <__strxfrm_l+0x297f>
   9bb10:	mov    -0x98(%rbp),%edi
   9bb16:	mov    %r15d,-0xc8(%rbp)
   9bb1d:	mov    %r11,-0xd0(%rbp)
   9bb24:	movzbl (%r12),%eax
   9bb29:	mov    -0x48(%rbp),%rbx
   9bb2d:	lea    0x1(%r12),%r15
   9bb32:	movslq (%rbx,%rax,4),%rax
   9bb36:	test   %rax,%rax
   9bb39:	mov    %rax,%rsi
   9bb3c:	js     9cdb6 <__strxfrm_l+0x3586>
   9bb42:	mov    %r15,%r12
   9bb45:	and    $0xffffff,%esi
   9bb4b:	test   %edi,%edi
   9bb4d:	lea    0x1(%rsi),%edx
   9bb50:	movslq %esi,%rsi
   9bb53:	movzbl (%r14,%rsi,1),%eax
   9bb58:	jle    9bb73 <__strxfrm_l+0x2343>
   9bb5a:	xor    %ecx,%ecx
   9bb5c:	nopl   0x0(%rax)
   9bb60:	add    %edx,%eax
   9bb62:	add    $0x1,%ecx
   9bb65:	lea    0x1(%rax),%edx
   9bb68:	cmp    %ecx,%edi
   9bb6a:	cltq   
   9bb6c:	movzbl (%r14,%rax,1),%eax
   9bb71:	jne    9bb60 <__strxfrm_l+0x2330>
   9bb73:	mov    -0x58(%rbp),%r8
   9bb77:	add    -0x50(%rbp),%r8
   9bb7b:	cmp    %r8,-0x68(%rbp)
   9bb7f:	jbe    9c197 <__strxfrm_l+0x2967>
   9bb85:	test   %rax,%rax
   9bb88:	je     9c197 <__strxfrm_l+0x2967>
   9bb8e:	mov    %r13,%rsi
   9bb91:	movslq %edx,%r9
   9bb94:	mov    %r8,%rbx
   9bb97:	sub    %rax,%rsi
   9bb9a:	lea    (%r14,%r9,1),%rcx
   9bb9e:	sub    %rax,%rbx
   9bba1:	lea    0x10(%rsi,%r8,1),%rsi
   9bba6:	lea    0x0(%r13,%rbx,1),%r10
   9bbab:	mov    %rbx,-0xa8(%rbp)
   9bbb2:	cmp    %rsi,%rcx
   9bbb5:	lea    0x10(%r14,%r9,1),%rsi
   9bbba:	setae  %r11b
   9bbbe:	cmp    %rsi,%r10
   9bbc1:	setae  %sil
   9bbc5:	or     %sil,%r11b
   9bbc8:	je     9cf57 <__strxfrm_l+0x3727>
   9bbce:	cmp    $0x14,%rax
   9bbd2:	jbe    9cf57 <__strxfrm_l+0x3727>
   9bbd8:	mov    %rcx,%rsi
   9bbdb:	neg    %rsi
   9bbde:	and    $0xf,%esi
   9bbe1:	je     9cf40 <__strxfrm_l+0x3710>
   9bbe7:	movzbl (%rcx),%ecx
   9bbea:	lea    -0x1(%rax),%r11
   9bbee:	cmp    $0x1,%rsi
   9bbf2:	lea    0x1(%rdx),%ebx
   9bbf5:	mov    %cl,(%r10)
   9bbf8:	mov    %r11,%rcx
   9bbfb:	je     9cf29 <__strxfrm_l+0x36f9>
   9bc01:	movslq %ebx,%r10
   9bc04:	mov    %r8,%rcx
   9bc07:	lea    0x2(%rdx),%r15d
   9bc0b:	movzbl (%r14,%r10,1),%r10d
   9bc10:	sub    %r11,%rcx
   9bc13:	cmp    $0x2,%rsi
   9bc17:	mov    %r10b,0x0(%r13,%rcx,1)
   9bc1c:	lea    -0x2(%rax),%rcx
   9bc20:	je     9cf21 <__strxfrm_l+0x36f1>
   9bc26:	mov    %r8,%r10
   9bc29:	lea    0x3(%rdx),%ebx
   9bc2c:	sub    %rcx,%r10
   9bc2f:	cmp    $0x3,%rsi
   9bc33:	mov    %r10,%rcx
   9bc36:	movslq %r15d,%r10
   9bc39:	movzbl (%r14,%r10,1),%r10d
   9bc3e:	mov    %r10b,0x0(%r13,%rcx,1)
   9bc43:	lea    -0x3(%rax),%rcx
   9bc47:	je     9cf29 <__strxfrm_l+0x36f9>
   9bc4d:	mov    %r8,%r10
   9bc50:	lea    0x4(%rdx),%r15d
   9bc54:	sub    %rcx,%r10
   9bc57:	cmp    $0x4,%rsi
   9bc5b:	mov    %r10,%rcx
   9bc5e:	movslq %ebx,%r10
   9bc61:	movzbl (%r14,%r10,1),%r10d
   9bc66:	mov    %r10b,0x0(%r13,%rcx,1)
   9bc6b:	lea    -0x4(%rax),%rcx
   9bc6f:	je     9cf21 <__strxfrm_l+0x36f1>
   9bc75:	mov    %r8,%r10
   9bc78:	lea    0x5(%rdx),%ebx
   9bc7b:	sub    %rcx,%r10
   9bc7e:	cmp    $0x5,%rsi
   9bc82:	mov    %r10,%rcx
   9bc85:	movslq %r15d,%r10
   9bc88:	movzbl (%r14,%r10,1),%r10d
   9bc8d:	mov    %r10b,0x0(%r13,%rcx,1)
   9bc92:	lea    -0x5(%rax),%rcx
   9bc96:	je     9cf29 <__strxfrm_l+0x36f9>
   9bc9c:	mov    %r8,%r10
   9bc9f:	lea    0x6(%rdx),%r15d
   9bca3:	sub    %rcx,%r10
   9bca6:	cmp    $0x6,%rsi
   9bcaa:	mov    %r10,%rcx
   9bcad:	movslq %ebx,%r10
   9bcb0:	movzbl (%r14,%r10,1),%r10d
   9bcb5:	mov    %r10b,0x0(%r13,%rcx,1)
   9bcba:	lea    -0x6(%rax),%rcx
   9bcbe:	je     9cf21 <__strxfrm_l+0x36f1>
   9bcc4:	mov    %r8,%r10
   9bcc7:	lea    0x7(%rdx),%ebx
   9bcca:	sub    %rcx,%r10
   9bccd:	cmp    $0x7,%rsi
   9bcd1:	mov    %r10,%rcx
   9bcd4:	movslq %r15d,%r10
   9bcd7:	movzbl (%r14,%r10,1),%r10d
   9bcdc:	mov    %r10b,0x0(%r13,%rcx,1)
   9bce1:	lea    -0x7(%rax),%rcx
   9bce5:	je     9cf29 <__strxfrm_l+0x36f9>
   9bceb:	mov    %r8,%r10
   9bcee:	lea    0x8(%rdx),%r15d
   9bcf2:	sub    %rcx,%r10
   9bcf5:	cmp    $0x8,%rsi
   9bcf9:	mov    %r10,%rcx
   9bcfc:	movslq %ebx,%r10
   9bcff:	movzbl (%r14,%r10,1),%r10d
   9bd04:	mov    %r10b,0x0(%r13,%rcx,1)
   9bd09:	lea    -0x8(%rax),%rcx
   9bd0d:	je     9cf21 <__strxfrm_l+0x36f1>
   9bd13:	mov    %r8,%r10
   9bd16:	lea    0x9(%rdx),%ebx
   9bd19:	sub    %rcx,%r10
   9bd1c:	cmp    $0x9,%rsi
   9bd20:	mov    %r10,%rcx
   9bd23:	movslq %r15d,%r10
   9bd26:	movzbl (%r14,%r10,1),%r10d
   9bd2b:	mov    %r10b,0x0(%r13,%rcx,1)
   9bd30:	lea    -0x9(%rax),%rcx
   9bd34:	je     9cf29 <__strxfrm_l+0x36f9>
   9bd3a:	mov    %r8,%r10
   9bd3d:	lea    0xa(%rdx),%r15d
   9bd41:	sub    %rcx,%r10
   9bd44:	cmp    $0xa,%rsi
   9bd48:	mov    %r10,%rcx
   9bd4b:	movslq %ebx,%r10
   9bd4e:	movzbl (%r14,%r10,1),%r10d
   9bd53:	mov    %r10b,0x0(%r13,%rcx,1)
   9bd58:	lea    -0xa(%rax),%rcx
   9bd5c:	je     9cf21 <__strxfrm_l+0x36f1>
   9bd62:	mov    %r8,%r10
   9bd65:	lea    0xb(%rdx),%ebx
   9bd68:	sub    %rcx,%r10
   9bd6b:	cmp    $0xb,%rsi
   9bd6f:	mov    %r10,%rcx
   9bd72:	movslq %r15d,%r10
   9bd75:	movzbl (%r14,%r10,1),%r10d
   9bd7a:	mov    %r10b,0x0(%r13,%rcx,1)
   9bd7f:	lea    -0xb(%rax),%rcx
   9bd83:	je     9cf29 <__strxfrm_l+0x36f9>
   9bd89:	mov    %r8,%r10
   9bd8c:	lea    0xc(%rdx),%r15d
   9bd90:	sub    %rcx,%r10
   9bd93:	cmp    $0xc,%rsi
   9bd97:	mov    %r10,%rcx
   9bd9a:	movslq %ebx,%r10
   9bd9d:	movzbl (%r14,%r10,1),%r10d
   9bda2:	mov    %r10b,0x0(%r13,%rcx,1)
   9bda7:	lea    -0xc(%rax),%rcx
   9bdab:	je     9cf21 <__strxfrm_l+0x36f1>
   9bdb1:	mov    %r8,%r10
   9bdb4:	lea    0xd(%rdx),%ebx
   9bdb7:	sub    %rcx,%r10
   9bdba:	cmp    $0xd,%rsi
   9bdbe:	mov    %r10,%rcx
   9bdc1:	movslq %r15d,%r10
   9bdc4:	movzbl (%r14,%r10,1),%r10d
   9bdc9:	mov    %r10b,0x0(%r13,%rcx,1)
   9bdce:	lea    -0xd(%rax),%rcx
   9bdd2:	je     9cf29 <__strxfrm_l+0x36f9>
   9bdd8:	mov    %r8,%r10
   9bddb:	lea    0xe(%rdx),%r15d
   9bddf:	sub    %rcx,%r10
   9bde2:	cmp    $0xf,%rsi
   9bde6:	mov    %r10,%rcx
   9bde9:	movslq %ebx,%r10
   9bdec:	movzbl (%r14,%r10,1),%r10d
   9bdf1:	mov    %r10b,0x0(%r13,%rcx,1)
   9bdf6:	lea    -0xe(%rax),%rcx
   9bdfa:	jne    9cf21 <__strxfrm_l+0x36f1>
   9be00:	movslq %r15d,%r10
   9be03:	mov    %r8,%rbx
   9be06:	add    $0xf,%edx
   9be09:	movzbl (%r14,%r10,1),%r10d
   9be0e:	sub    %rcx,%rbx
   9be11:	lea    -0xf(%rax),%rcx
   9be15:	mov    %r10b,0x0(%r13,%rbx,1)
   9be1a:	mov    %rax,%r15
   9be1d:	sub    %rsi,%r11
   9be20:	sub    %rsi,%r15
   9be23:	lea    -0x10(%r15),%r10
   9be27:	shr    $0x4,%r10
   9be2b:	add    $0x1,%r10
   9be2f:	mov    %r10,%rbx
   9be32:	shl    $0x4,%rbx
   9be36:	cmp    $0xe,%r11
   9be3a:	jbe    9bfaa <__strxfrm_l+0x277a>
   9be40:	add    %rsi,%r9
   9be43:	add    -0xa8(%rbp),%rsi
   9be4a:	add    %r14,%r9
   9be4d:	movdqa (%r9),%xmm0
   9be52:	add    %r13,%rsi
   9be55:	cmp    $0x1,%r10
   9be59:	movups %xmm0,(%rsi)
   9be5c:	je     9bf9c <__strxfrm_l+0x276c>
   9be62:	cmp    $0x2,%r10
   9be66:	movdqa 0x10(%r9),%xmm0
   9be6c:	movups %xmm0,0x10(%rsi)
   9be70:	je     9bf9c <__strxfrm_l+0x276c>
   9be76:	cmp    $0x3,%r10
   9be7a:	movdqa 0x20(%r9),%xmm0
   9be80:	movups %xmm0,0x20(%rsi)
   9be84:	je     9bf9c <__strxfrm_l+0x276c>
   9be8a:	cmp    $0x4,%r10
   9be8e:	movdqa 0x30(%r9),%xmm0
   9be94:	movups %xmm0,0x30(%rsi)
   9be98:	je     9bf9c <__strxfrm_l+0x276c>
   9be9e:	cmp    $0x5,%r10
   9bea2:	movdqa 0x40(%r9),%xmm0
   9bea8:	movups %xmm0,0x40(%rsi)
   9beac:	je     9bf9c <__strxfrm_l+0x276c>
   9beb2:	cmp    $0x6,%r10
   9beb6:	movdqa 0x50(%r9),%xmm0
   9bebc:	movups %xmm0,0x50(%rsi)
   9bec0:	je     9bf9c <__strxfrm_l+0x276c>
   9bec6:	cmp    $0x7,%r10
   9beca:	movdqa 0x60(%r9),%xmm0
   9bed0:	movups %xmm0,0x60(%rsi)
   9bed4:	je     9bf9c <__strxfrm_l+0x276c>
   9beda:	cmp    $0x8,%r10
   9bede:	movdqa 0x70(%r9),%xmm0
   9bee4:	movups %xmm0,0x70(%rsi)
   9bee8:	je     9bf9c <__strxfrm_l+0x276c>
   9beee:	cmp    $0x9,%r10
   9bef2:	movdqa 0x80(%r9),%xmm0
   9befb:	movups %xmm0,0x80(%rsi)
   9bf02:	je     9bf9c <__strxfrm_l+0x276c>
   9bf08:	cmp    $0xa,%r10
   9bf0c:	movdqa 0x90(%r9),%xmm0
   9bf15:	movups %xmm0,0x90(%rsi)
   9bf1c:	je     9bf9c <__strxfrm_l+0x276c>
   9bf1e:	cmp    $0xb,%r10
   9bf22:	movdqa 0xa0(%r9),%xmm0
   9bf2b:	movups %xmm0,0xa0(%rsi)
   9bf32:	je     9bf9c <__strxfrm_l+0x276c>
   9bf34:	cmp    $0xc,%r10
   9bf38:	movdqa 0xb0(%r9),%xmm0
   9bf41:	movups %xmm0,0xb0(%rsi)
   9bf48:	je     9bf9c <__strxfrm_l+0x276c>
   9bf4a:	cmp    $0xd,%r10
   9bf4e:	movdqa 0xc0(%r9),%xmm0
   9bf57:	movups %xmm0,0xc0(%rsi)
   9bf5e:	je     9bf9c <__strxfrm_l+0x276c>
   9bf60:	cmp    $0xe,%r10
   9bf64:	movdqa 0xd0(%r9),%xmm0
   9bf6d:	movups %xmm0,0xd0(%rsi)
   9bf74:	je     9bf9c <__strxfrm_l+0x276c>
   9bf76:	cmp    $0xf,%r10
   9bf7a:	movdqa 0xe0(%r9),%xmm0
   9bf83:	movups %xmm0,0xe0(%rsi)
   9bf8a:	je     9bf9c <__strxfrm_l+0x276c>
   9bf8c:	movdqa 0xf0(%r9),%xmm0
   9bf95:	movups %xmm0,0xf0(%rsi)
   9bf9c:	sub    %rbx,%rcx
   9bf9f:	add    %ebx,%edx
   9bfa1:	cmp    %r15,%rbx
   9bfa4:	je     9c197 <__strxfrm_l+0x2967>
   9bfaa:	movslq %edx,%r10
   9bfad:	mov    %r8,%r9
   9bfb0:	lea    0x1(%rdx),%esi
   9bfb3:	movzbl (%r14,%r10,1),%r10d
   9bfb8:	sub    %rcx,%r9
   9bfbb:	mov    %r10b,0x0(%r13,%r9,1)
   9bfc0:	mov    %rcx,%r10
   9bfc3:	sub    $0x1,%r10
   9bfc7:	je     9c197 <__strxfrm_l+0x2967>
   9bfcd:	movslq %esi,%rsi
   9bfd0:	mov    %r8,%rbx
   9bfd3:	lea    0x2(%rdx),%r9d
   9bfd7:	movzbl (%r14,%rsi,1),%esi
   9bfdc:	sub    %r10,%rbx
   9bfdf:	mov    %rcx,%r10
   9bfe2:	sub    $0x2,%r10
   9bfe6:	mov    %sil,0x0(%r13,%rbx,1)
   9bfeb:	je     9c197 <__strxfrm_l+0x2967>
   9bff1:	movslq %r9d,%r9
   9bff4:	mov    %r8,%rbx
   9bff7:	lea    0x3(%rdx),%esi
   9bffa:	movzbl (%r14,%r9,1),%r9d
   9bfff:	sub    %r10,%rbx
   9c002:	mov    %rcx,%r10
   9c005:	sub    $0x3,%r10
   9c009:	mov    %r9b,0x0(%r13,%rbx,1)
   9c00e:	je     9c197 <__strxfrm_l+0x2967>
   9c014:	movslq %esi,%rsi
   9c017:	mov    %r8,%rbx
   9c01a:	lea    0x4(%rdx),%r9d
   9c01e:	movzbl (%r14,%rsi,1),%esi
   9c023:	sub    %r10,%rbx
   9c026:	mov    %rcx,%r10
   9c029:	sub    $0x4,%r10
   9c02d:	mov    %sil,0x0(%r13,%rbx,1)
   9c032:	je     9c197 <__strxfrm_l+0x2967>
   9c038:	movslq %r9d,%r9
   9c03b:	mov    %r8,%rbx
   9c03e:	lea    0x5(%rdx),%esi
   9c041:	movzbl (%r14,%r9,1),%r9d
   9c046:	sub    %r10,%rbx
   9c049:	mov    %rcx,%r10
   9c04c:	sub    $0x5,%r10
   9c050:	mov    %r9b,0x0(%r13,%rbx,1)
   9c055:	je     9c197 <__strxfrm_l+0x2967>
   9c05b:	movslq %esi,%rsi
   9c05e:	mov    %r8,%rbx
   9c061:	lea    0x6(%rdx),%r9d
   9c065:	movzbl (%r14,%rsi,1),%esi
   9c06a:	sub    %r10,%rbx
   9c06d:	mov    %rcx,%r10
   9c070:	sub    $0x6,%r10
   9c074:	mov    %sil,0x0(%r13,%rbx,1)
   9c079:	je     9c197 <__strxfrm_l+0x2967>
   9c07f:	movslq %r9d,%r9
   9c082:	mov    %r8,%rbx
   9c085:	lea    0x7(%rdx),%esi
   9c088:	movzbl (%r14,%r9,1),%r9d
   9c08d:	sub    %r10,%rbx
   9c090:	mov    %rcx,%r10
   9c093:	sub    $0x7,%r10
   9c097:	mov    %r9b,0x0(%r13,%rbx,1)
   9c09c:	je     9c197 <__strxfrm_l+0x2967>
   9c0a2:	movslq %esi,%rsi
   9c0a5:	mov    %r8,%rbx
   9c0a8:	lea    0x8(%rdx),%r9d
   9c0ac:	movzbl (%r14,%rsi,1),%esi
   9c0b1:	sub    %r10,%rbx
   9c0b4:	mov    %rcx,%r10
   9c0b7:	sub    $0x8,%r10
   9c0bb:	mov    %sil,0x0(%r13,%rbx,1)
   9c0c0:	je     9c197 <__strxfrm_l+0x2967>
   9c0c6:	movslq %r9d,%r9
   9c0c9:	mov    %r8,%rbx
   9c0cc:	lea    0x9(%rdx),%esi
   9c0cf:	movzbl (%r14,%r9,1),%r9d
   9c0d4:	sub    %r10,%rbx
   9c0d7:	mov    %rcx,%r10
   9c0da:	sub    $0x9,%r10
   9c0de:	mov    %r9b,0x0(%r13,%rbx,1)
   9c0e3:	je     9c197 <__strxfrm_l+0x2967>
   9c0e9:	movslq %esi,%rsi
   9c0ec:	mov    %r8,%rbx
   9c0ef:	lea    0xa(%rdx),%r9d
   9c0f3:	movzbl (%r14,%rsi,1),%esi
   9c0f8:	sub    %r10,%rbx
   9c0fb:	mov    %rcx,%r10
   9c0fe:	sub    $0xa,%r10
   9c102:	mov    %sil,0x0(%r13,%rbx,1)
   9c107:	je     9c197 <__strxfrm_l+0x2967>
   9c10d:	movslq %r9d,%r9
   9c110:	mov    %r8,%rbx
   9c113:	lea    0xb(%rdx),%esi
   9c116:	movzbl (%r14,%r9,1),%r9d
   9c11b:	sub    %r10,%rbx
   9c11e:	mov    %rcx,%r10
   9c121:	sub    $0xb,%r10
   9c125:	mov    %r9b,0x0(%r13,%rbx,1)
   9c12a:	je     9c197 <__strxfrm_l+0x2967>
   9c12c:	movslq %esi,%rsi
   9c12f:	mov    %r8,%rbx
   9c132:	lea    0xc(%rdx),%r9d
   9c136:	movzbl (%r14,%rsi,1),%esi
   9c13b:	sub    %r10,%rbx
   9c13e:	mov    %rcx,%r10
   9c141:	sub    $0xc,%r10
   9c145:	mov    %sil,0x0(%r13,%rbx,1)
   9c14a:	je     9c197 <__strxfrm_l+0x2967>
   9c14c:	movslq %r9d,%r9
   9c14f:	mov    %r8,%rbx
   9c152:	lea    0xd(%rdx),%esi
   9c155:	movzbl (%r14,%r9,1),%r9d
   9c15a:	sub    %r10,%rbx
   9c15d:	mov    %r9b,0x0(%r13,%rbx,1)
   9c162:	mov    %rcx,%r9
   9c165:	sub    $0xd,%r9
   9c169:	je     9c197 <__strxfrm_l+0x2967>
   9c16b:	movslq %esi,%rsi
   9c16e:	mov    %r8,%rbx
   9c171:	add    $0xe,%edx
   9c174:	movzbl (%r14,%rsi,1),%esi
   9c179:	sub    %r9,%rbx
   9c17c:	sub    $0xe,%rcx
   9c180:	mov    %sil,0x0(%r13,%rbx,1)
   9c185:	je     9c197 <__strxfrm_l+0x2967>
   9c187:	movslq %edx,%rdx
   9c18a:	sub    %rcx,%r8
   9c18d:	movzbl (%r14,%rdx,1),%edx
   9c192:	mov    %dl,0x0(%r13,%r8,1)
   9c197:	sub    %rax,-0x50(%rbp)
   9c19b:	jne    9bb24 <__strxfrm_l+0x22f4>
   9c1a1:	mov    -0xc8(%rbp),%r15d
   9c1a8:	mov    -0xd0(%rbp),%r11
   9c1af:	mov    -0x58(%rbp),%rdx
   9c1b3:	add    -0x60(%rbp),%rdx
   9c1b7:	movq   $0x0,-0x60(%rbp)
   9c1bf:	lea    (%rdx,%r11,1),%rax
   9c1c3:	xor    %r12d,%r12d
   9c1c6:	cmp    %rax,-0x68(%rbp)
   9c1ca:	mov    %rax,-0x58(%rbp)
   9c1ce:	jbe    9c712 <__strxfrm_l+0x2ee2>
   9c1d4:	test   %r11,%r11
   9c1d7:	lea    -0x1(%r11),%r10
   9c1db:	je     9f878 <__strxfrm_l+0x6048>
   9c1e1:	movslq %r15d,%r8
   9c1e4:	lea    0x0(%r13,%rdx,1),%r9
   9c1e9:	lea    0x10(%r14,%r8,1),%rax
   9c1ee:	lea    (%r14,%r8,1),%rdi
   9c1f2:	cmp    %rax,%r9
   9c1f5:	lea    0x10(%r13,%rdx,1),%rax
   9c1fa:	setae  %cl
   9c1fd:	cmp    %rax,%rdi
   9c200:	setae  %al
   9c203:	or     %al,%cl
   9c205:	je     9f860 <__strxfrm_l+0x6030>
   9c20b:	cmp    $0x14,%r11
   9c20f:	jbe    9f860 <__strxfrm_l+0x6030>
   9c215:	mov    %rdi,%rax
   9c218:	neg    %rax
   9c21b:	and    $0xf,%eax
   9c21e:	je     9d36d <__strxfrm_l+0x3b3d>
   9c224:	movzbl (%rdi),%edi
   9c227:	cmp    $0x1,%rax
   9c22b:	lea    0x1(%rdx),%rsi
   9c22f:	lea    0x1(%r15),%ecx
   9c233:	mov    %dil,(%r9)
   9c236:	lea    -0x2(%r11),%rdi
   9c23a:	je     9c418 <__strxfrm_l+0x2be8>
   9c240:	movslq %ecx,%rcx
   9c243:	cmp    $0x2,%rax
   9c247:	lea    0x2(%rdx),%rsi
   9c24b:	movzbl (%r14,%rcx,1),%ecx
   9c250:	lea    0x2(%r15),%r9d
   9c254:	lea    -0x3(%r11),%rdi
   9c258:	mov    %cl,0x1(%r13,%rdx,1)
   9c25d:	je     9f881 <__strxfrm_l+0x6051>
   9c263:	movslq %r9d,%r9
   9c266:	cmp    $0x3,%rax
   9c26a:	lea    0x3(%rdx),%rsi
   9c26e:	movzbl (%r14,%r9,1),%edi
   9c273:	lea    0x3(%r15),%ecx
   9c277:	mov    %dil,0x2(%r13,%rdx,1)
   9c27c:	lea    -0x4(%r11),%rdi
   9c280:	je     9c418 <__strxfrm_l+0x2be8>
   9c286:	movslq %ecx,%rcx
   9c289:	cmp    $0x4,%rax
   9c28d:	lea    0x4(%rdx),%rsi
   9c291:	movzbl (%r14,%rcx,1),%ecx
   9c296:	lea    0x4(%r15),%r9d
   9c29a:	lea    -0x5(%r11),%rdi
   9c29e:	mov    %cl,0x3(%r13,%rdx,1)
   9c2a3:	je     9f881 <__strxfrm_l+0x6051>
   9c2a9:	movslq %r9d,%r9
   9c2ac:	cmp    $0x5,%rax
   9c2b0:	lea    0x5(%rdx),%rsi
   9c2b4:	movzbl (%r14,%r9,1),%edi
   9c2b9:	lea    0x5(%r15),%ecx
   9c2bd:	mov    %dil,0x4(%r13,%rdx,1)
   9c2c2:	lea    -0x6(%r11),%rdi
   9c2c6:	je     9c418 <__strxfrm_l+0x2be8>
   9c2cc:	movslq %ecx,%rcx
   9c2cf:	cmp    $0x6,%rax
   9c2d3:	lea    0x6(%rdx),%rsi
   9c2d7:	movzbl (%r14,%rcx,1),%ecx
   9c2dc:	lea    0x6(%r15),%r9d
   9c2e0:	lea    -0x7(%r11),%rdi
   9c2e4:	mov    %cl,0x5(%r13,%rdx,1)
   9c2e9:	je     9f881 <__strxfrm_l+0x6051>
   9c2ef:	movslq %r9d,%r9
   9c2f2:	cmp    $0x7,%rax
   9c2f6:	lea    0x7(%rdx),%rsi
   9c2fa:	movzbl (%r14,%r9,1),%edi
   9c2ff:	lea    0x7(%r15),%ecx
   9c303:	mov    %dil,0x6(%r13,%rdx,1)
   9c308:	lea    -0x8(%r11),%rdi
   9c30c:	je     9c418 <__strxfrm_l+0x2be8>
   9c312:	movslq %ecx,%rcx
   9c315:	cmp    $0x8,%rax
   9c319:	lea    0x8(%rdx),%rsi
   9c31d:	movzbl (%r14,%rcx,1),%ecx
   9c322:	lea    0x8(%r15),%r9d
   9c326:	lea    -0x9(%r11),%rdi
   9c32a:	mov    %cl,0x7(%r13,%rdx,1)
   9c32f:	je     9f881 <__strxfrm_l+0x6051>
   9c335:	movslq %r9d,%r9
   9c338:	cmp    $0x9,%rax
   9c33c:	lea    0x9(%rdx),%rsi
   9c340:	movzbl (%r14,%r9,1),%edi
   9c345:	lea    0x9(%r15),%ecx
   9c349:	mov    %dil,0x8(%r13,%rdx,1)
   9c34e:	lea    -0xa(%r11),%rdi
   9c352:	je     9c418 <__strxfrm_l+0x2be8>
   9c358:	movslq %ecx,%rcx
   9c35b:	cmp    $0xa,%rax
   9c35f:	lea    0xa(%rdx),%rsi
   9c363:	movzbl (%r14,%rcx,1),%ecx
   9c368:	lea    0xa(%r15),%r9d
   9c36c:	lea    -0xb(%r11),%rdi
   9c370:	mov    %cl,0x9(%r13,%rdx,1)
   9c375:	je     9f881 <__strxfrm_l+0x6051>
   9c37b:	movslq %r9d,%r9
   9c37e:	cmp    $0xb,%rax
   9c382:	lea    0xb(%rdx),%rsi
   9c386:	movzbl (%r14,%r9,1),%edi
   9c38b:	lea    0xb(%r15),%ecx
   9c38f:	mov    %dil,0xa(%r13,%rdx,1)
   9c394:	lea    -0xc(%r11),%rdi
   9c398:	je     9c418 <__strxfrm_l+0x2be8>
   9c39a:	movslq %ecx,%rcx
   9c39d:	cmp    $0xc,%rax
   9c3a1:	lea    0xc(%rdx),%rsi
   9c3a5:	movzbl (%r14,%rcx,1),%ecx
   9c3aa:	lea    0xc(%r15),%r9d
   9c3ae:	lea    -0xd(%r11),%rdi
   9c3b2:	mov    %cl,0xb(%r13,%rdx,1)
   9c3b7:	je     9f881 <__strxfrm_l+0x6051>
   9c3bd:	movslq %r9d,%r9
   9c3c0:	cmp    $0xd,%rax
   9c3c4:	lea    0xd(%rdx),%rsi
   9c3c8:	movzbl (%r14,%r9,1),%edi
   9c3cd:	lea    0xd(%r15),%ecx
   9c3d1:	mov    %dil,0xc(%r13,%rdx,1)
   9c3d6:	lea    -0xe(%r11),%rdi
   9c3da:	je     9c418 <__strxfrm_l+0x2be8>
   9c3dc:	movslq %ecx,%rcx
   9c3df:	cmp    $0xf,%rax
   9c3e3:	lea    0xe(%rdx),%rsi
   9c3e7:	movzbl (%r14,%rcx,1),%ecx
   9c3ec:	lea    0xe(%r15),%r9d
   9c3f0:	lea    -0xf(%r11),%rdi
   9c3f4:	mov    %cl,0xd(%r13,%rdx,1)
   9c3f9:	jne    9f881 <__strxfrm_l+0x6051>
   9c3ff:	movslq %r9d,%r9
   9c402:	lea    0xf(%rdx),%rsi
   9c406:	lea    0xf(%r15),%ecx
   9c40a:	movzbl (%r14,%r9,1),%edi
   9c40f:	mov    %dil,0xe(%r13,%rdx,1)
   9c414:	lea    -0x10(%r11),%rdi
   9c418:	mov    %ecx,%r15d
   9c41b:	sub    %rax,%r11
   9c41e:	sub    %rax,%r10
   9c421:	lea    -0x10(%r11),%rcx
   9c425:	shr    $0x4,%rcx
   9c429:	add    $0x1,%rcx
   9c42d:	mov    %rcx,%r9
   9c430:	shl    $0x4,%r9
   9c434:	cmp    $0xe,%r10
   9c438:	jbe    9c5a8 <__strxfrm_l+0x2d78>
   9c43e:	add    %rax,%r8
   9c441:	add    %rdx,%rax
   9c444:	add    %r14,%r8
   9c447:	add    %r13,%rax
   9c44a:	cmp    $0x1,%rcx
   9c44e:	movdqa (%r8),%xmm0
   9c453:	movups %xmm0,(%rax)
   9c456:	je     9c596 <__strxfrm_l+0x2d66>
   9c45c:	cmp    $0x2,%rcx
   9c460:	movdqa 0x10(%r8),%xmm0
   9c466:	movups %xmm0,0x10(%rax)
   9c46a:	je     9c596 <__strxfrm_l+0x2d66>
   9c470:	cmp    $0x3,%rcx
   9c474:	movdqa 0x20(%r8),%xmm0
   9c47a:	movups %xmm0,0x20(%rax)
   9c47e:	je     9c596 <__strxfrm_l+0x2d66>
   9c484:	cmp    $0x4,%rcx
   9c488:	movdqa 0x30(%r8),%xmm0
   9c48e:	movups %xmm0,0x30(%rax)
   9c492:	je     9c596 <__strxfrm_l+0x2d66>
   9c498:	cmp    $0x5,%rcx
   9c49c:	movdqa 0x40(%r8),%xmm0
   9c4a2:	movups %xmm0,0x40(%rax)
   9c4a6:	je     9c596 <__strxfrm_l+0x2d66>
   9c4ac:	cmp    $0x6,%rcx
   9c4b0:	movdqa 0x50(%r8),%xmm0
   9c4b6:	movups %xmm0,0x50(%rax)
   9c4ba:	je     9c596 <__strxfrm_l+0x2d66>
   9c4c0:	cmp    $0x7,%rcx
   9c4c4:	movdqa 0x60(%r8),%xmm0
   9c4ca:	movups %xmm0,0x60(%rax)
   9c4ce:	je     9c596 <__strxfrm_l+0x2d66>
   9c4d4:	cmp    $0x8,%rcx
   9c4d8:	movdqa 0x70(%r8),%xmm0
   9c4de:	movups %xmm0,0x70(%rax)
   9c4e2:	je     9c596 <__strxfrm_l+0x2d66>
   9c4e8:	cmp    $0x9,%rcx
   9c4ec:	movdqa 0x80(%r8),%xmm0
   9c4f5:	movups %xmm0,0x80(%rax)
   9c4fc:	je     9c596 <__strxfrm_l+0x2d66>
   9c502:	cmp    $0xa,%rcx
   9c506:	movdqa 0x90(%r8),%xmm0
   9c50f:	movups %xmm0,0x90(%rax)
   9c516:	je     9c596 <__strxfrm_l+0x2d66>
   9c518:	cmp    $0xb,%rcx
   9c51c:	movdqa 0xa0(%r8),%xmm0
   9c525:	movups %xmm0,0xa0(%rax)
   9c52c:	je     9c596 <__strxfrm_l+0x2d66>
   9c52e:	cmp    $0xc,%rcx
   9c532:	movdqa 0xb0(%r8),%xmm0
   9c53b:	movups %xmm0,0xb0(%rax)
   9c542:	je     9c596 <__strxfrm_l+0x2d66>
   9c544:	cmp    $0xd,%rcx
   9c548:	movdqa 0xc0(%r8),%xmm0
   9c551:	movups %xmm0,0xc0(%rax)
   9c558:	je     9c596 <__strxfrm_l+0x2d66>
   9c55a:	cmp    $0xe,%rcx
   9c55e:	movdqa 0xd0(%r8),%xmm0
   9c567:	movups %xmm0,0xd0(%rax)
   9c56e:	je     9c596 <__strxfrm_l+0x2d66>
   9c570:	cmp    $0xf,%rcx
   9c574:	movdqa 0xe0(%r8),%xmm0
   9c57d:	movups %xmm0,0xe0(%rax)
   9c584:	je     9c596 <__strxfrm_l+0x2d66>
   9c586:	movdqa 0xf0(%r8),%xmm0
   9c58f:	movups %xmm0,0xf0(%rax)
   9c596:	add    %r9,%rsi
   9c599:	add    %r9d,%r15d
   9c59c:	sub    %r9,%rdi
   9c59f:	cmp    %r9,%r11
   9c5a2:	je     9c70f <__strxfrm_l+0x2edf>
   9c5a8:	movslq %r15d,%rdx
   9c5ab:	test   %rdi,%rdi
   9c5ae:	lea    0x1(%r15),%eax
   9c5b2:	movzbl (%r14,%rdx,1),%edx
   9c5b7:	mov    %dl,0x0(%r13,%rsi,1)
   9c5bc:	je     9c70f <__strxfrm_l+0x2edf>
   9c5c2:	cltq   
   9c5c4:	cmp    $0x1,%rdi
   9c5c8:	lea    0x2(%r15),%edx
   9c5cc:	movzbl (%r14,%rax,1),%eax
   9c5d1:	mov    %al,0x1(%r13,%rsi,1)
   9c5d6:	je     9c70f <__strxfrm_l+0x2edf>
   9c5dc:	movslq %edx,%rdx
   9c5df:	cmp    $0x2,%rdi
   9c5e3:	lea    0x3(%r15),%eax
   9c5e7:	movzbl (%r14,%rdx,1),%edx
   9c5ec:	mov    %dl,0x2(%r13,%rsi,1)
   9c5f1:	je     9c70f <__strxfrm_l+0x2edf>
   9c5f7:	cltq   
   9c5f9:	cmp    $0x3,%rdi
   9c5fd:	lea    0x4(%r15),%edx
   9c601:	movzbl (%r14,%rax,1),%eax
   9c606:	mov    %al,0x3(%r13,%rsi,1)
   9c60b:	je     9c70f <__strxfrm_l+0x2edf>
   9c611:	movslq %edx,%rdx
   9c614:	cmp    $0x4,%rdi
   9c618:	lea    0x5(%r15),%eax
   9c61c:	movzbl (%r14,%rdx,1),%edx
   9c621:	mov    %dl,0x4(%r13,%rsi,1)
   9c626:	je     9c70f <__strxfrm_l+0x2edf>
   9c62c:	cltq   
   9c62e:	cmp    $0x5,%rdi
   9c632:	lea    0x6(%r15),%edx
   9c636:	movzbl (%r14,%rax,1),%eax
   9c63b:	mov    %al,0x5(%r13,%rsi,1)
   9c640:	je     9c70f <__strxfrm_l+0x2edf>
   9c646:	movslq %edx,%rdx
   9c649:	cmp    $0x6,%rdi
   9c64d:	lea    0x7(%r15),%eax
   9c651:	movzbl (%r14,%rdx,1),%edx
   9c656:	mov    %dl,0x6(%r13,%rsi,1)
   9c65b:	je     9c70f <__strxfrm_l+0x2edf>
   9c661:	cltq   
   9c663:	cmp    $0x7,%rdi
   9c667:	lea    0x8(%r15),%edx
   9c66b:	movzbl (%r14,%rax,1),%eax
   9c670:	mov    %al,0x7(%r13,%rsi,1)
   9c675:	je     9c70f <__strxfrm_l+0x2edf>
   9c67b:	movslq %edx,%rdx
   9c67e:	cmp    $0x8,%rdi
   9c682:	lea    0x9(%r15),%eax
   9c686:	movzbl (%r14,%rdx,1),%edx
   9c68b:	mov    %dl,0x8(%r13,%rsi,1)
   9c690:	je     9c70f <__strxfrm_l+0x2edf>
   9c692:	cltq   
   9c694:	cmp    $0x9,%rdi
   9c698:	lea    0xa(%r15),%edx
   9c69c:	movzbl (%r14,%rax,1),%eax
   9c6a1:	mov    %al,0x9(%r13,%rsi,1)
   9c6a6:	je     9c70f <__strxfrm_l+0x2edf>
   9c6a8:	movslq %edx,%rdx
   9c6ab:	cmp    $0xa,%rdi
   9c6af:	lea    0xb(%r15),%eax
   9c6b3:	movzbl (%r14,%rdx,1),%edx
   9c6b8:	mov    %dl,0xa(%r13,%rsi,1)
   9c6bd:	je     9c70f <__strxfrm_l+0x2edf>
   9c6bf:	cltq   
   9c6c1:	cmp    $0xb,%rdi
   9c6c5:	lea    0xc(%r15),%edx
   9c6c9:	movzbl (%r14,%rax,1),%eax
   9c6ce:	mov    %al,0xb(%r13,%rsi,1)
   9c6d3:	je     9c70f <__strxfrm_l+0x2edf>
   9c6d5:	movslq %edx,%rdx
   9c6d8:	cmp    $0xc,%rdi
   9c6dc:	lea    0xd(%r15),%eax
   9c6e0:	movzbl (%r14,%rdx,1),%edx
   9c6e5:	mov    %dl,0xc(%r13,%rsi,1)
   9c6ea:	je     9c70f <__strxfrm_l+0x2edf>
   9c6ec:	cltq   
   9c6ee:	cmp    $0xd,%rdi
   9c6f2:	lea    0xe(%r15),%edx
   9c6f6:	movzbl (%r14,%rax,1),%eax
   9c6fb:	mov    %al,0xd(%r13,%rsi,1)
   9c700:	je     9c70f <__strxfrm_l+0x2edf>
   9c702:	movslq %edx,%rdx
   9c705:	movzbl (%r14,%rdx,1),%eax
   9c70a:	mov    %al,0xe(%r13,%rsi,1)
   9c70f:	xor    %r12d,%r12d
   9c712:	mov    -0x88(%rbp),%rbx
   9c719:	movzbl (%rbx),%eax
   9c71c:	test   %al,%al
   9c71e:	jne    9ba82 <__strxfrm_l+0x2252>
   9c724:	test   %r12,%r12
   9c727:	mov    -0x98(%rbp),%r15d
   9c72e:	je     99f88 <__strxfrm_l+0x758>
   9c734:	mov    -0x60(%rbp),%rax
   9c738:	test   %rax,%rax
   9c73b:	mov    %rax,-0x88(%rbp)
   9c742:	je     9cda9 <__strxfrm_l+0x3579>
   9c748:	movzbl (%r12),%eax
   9c74d:	mov    -0x48(%rbp),%rdi
   9c751:	lea    0x1(%r12),%r11
   9c756:	movslq (%rdi,%rax,4),%rax
   9c75a:	test   %rax,%rax
   9c75d:	mov    %rax,%rsi
   9c760:	js     9d0dc <__strxfrm_l+0x38ac>
   9c766:	mov    %r11,%r12
   9c769:	and    $0xffffff,%esi
   9c76f:	test   %r15d,%r15d
   9c772:	lea    0x1(%rsi),%r9d
   9c776:	movslq %esi,%rsi
   9c779:	movzbl (%r14,%rsi,1),%eax
   9c77e:	jle    9c798 <__strxfrm_l+0x2f68>
   9c780:	xor    %edx,%edx
   9c782:	add    %r9d,%eax
   9c785:	add    $0x1,%edx
   9c788:	lea    0x1(%rax),%r9d
   9c78c:	cmp    %edx,%r15d
   9c78f:	cltq   
   9c791:	movzbl (%r14,%rax,1),%eax
   9c796:	jne    9c782 <__strxfrm_l+0x2f52>
   9c798:	mov    -0x58(%rbp),%rdi
   9c79c:	add    -0x88(%rbp),%rdi
   9c7a3:	cmp    %rdi,-0x68(%rbp)
   9c7a7:	jbe    9cd9c <__strxfrm_l+0x356c>
   9c7ad:	test   %rax,%rax
   9c7b0:	je     9cd9c <__strxfrm_l+0x356c>
   9c7b6:	mov    %r13,%rcx
   9c7b9:	movslq %r9d,%r8
   9c7bc:	mov    %rdi,%rbx
   9c7bf:	sub    %rax,%rcx
   9c7c2:	lea    (%r14,%r8,1),%rdx
   9c7c6:	sub    %rax,%rbx
   9c7c9:	lea    0x10(%rcx,%rdi,1),%rcx
   9c7ce:	lea    0x0(%r13,%rbx,1),%r10
   9c7d3:	mov    %rbx,-0x50(%rbp)
   9c7d7:	cmp    %rcx,%rdx
   9c7da:	lea    0x10(%r14,%r8,1),%rcx
   9c7df:	setae  %sil
   9c7e3:	cmp    %rcx,%r10
   9c7e6:	setae  %cl
   9c7e9:	or     %cl,%sil
   9c7ec:	je     9d262 <__strxfrm_l+0x3a32>
   9c7f2:	cmp    $0x14,%rax
   9c7f6:	jbe    9d262 <__strxfrm_l+0x3a32>
   9c7fc:	mov    %rdx,%rsi
   9c7ff:	neg    %rsi
   9c802:	and    $0xf,%esi
   9c805:	je     9d253 <__strxfrm_l+0x3a23>
   9c80b:	movzbl (%rdx),%edx
   9c80e:	cmp    $0x1,%rsi
   9c812:	lea    0x1(%r9),%ecx
   9c816:	mov    %dl,(%r10)
   9c819:	lea    -0x1(%rax),%r10
   9c81d:	mov    %r10,%rdx
   9c820:	je     9ca1e <__strxfrm_l+0x31ee>
   9c826:	movslq %ecx,%rcx
   9c829:	mov    %rdi,%rdx
   9c82c:	lea    0x2(%r9),%r11d
   9c830:	movzbl (%r14,%rcx,1),%ecx
   9c835:	sub    %r10,%rdx
   9c838:	cmp    $0x2,%rsi
   9c83c:	mov    %cl,0x0(%r13,%rdx,1)
   9c841:	lea    -0x2(%rax),%rdx
   9c845:	je     9d40d <__strxfrm_l+0x3bdd>
   9c84b:	movslq %r11d,%r11
   9c84e:	mov    %rdi,%rbx
   9c851:	lea    0x3(%r9),%ecx
   9c855:	movzbl (%r14,%r11,1),%r11d
   9c85a:	sub    %rdx,%rbx
   9c85d:	cmp    $0x3,%rsi
   9c861:	lea    -0x3(%rax),%rdx
   9c865:	mov    %r11b,0x0(%r13,%rbx,1)
   9c86a:	je     9ca1e <__strxfrm_l+0x31ee>
   9c870:	movslq %ecx,%rcx
   9c873:	mov    %rdi,%rbx
   9c876:	lea    0x4(%r9),%r11d
   9c87a:	movzbl (%r14,%rcx,1),%ecx
   9c87f:	sub    %rdx,%rbx
   9c882:	cmp    $0x4,%rsi
   9c886:	lea    -0x4(%rax),%rdx
   9c88a:	mov    %cl,0x0(%r13,%rbx,1)
   9c88f:	je     9d40d <__strxfrm_l+0x3bdd>
   9c895:	movslq %r11d,%r11
   9c898:	mov    %rdi,%rbx
   9c89b:	lea    0x5(%r9),%ecx
   9c89f:	movzbl (%r14,%r11,1),%r11d
   9c8a4:	sub    %rdx,%rbx
   9c8a7:	cmp    $0x5,%rsi
   9c8ab:	lea    -0x5(%rax),%rdx
   9c8af:	mov    %r11b,0x0(%r13,%rbx,1)
   9c8b4:	je     9ca1e <__strxfrm_l+0x31ee>
   9c8ba:	movslq %ecx,%rcx
   9c8bd:	mov    %rdi,%rbx
   9c8c0:	lea    0x6(%r9),%r11d
   9c8c4:	movzbl (%r14,%rcx,1),%ecx
   9c8c9:	sub    %rdx,%rbx
   9c8cc:	cmp    $0x6,%rsi
   9c8d0:	lea    -0x6(%rax),%rdx
   9c8d4:	mov    %cl,0x0(%r13,%rbx,1)
   9c8d9:	je     9d40d <__strxfrm_l+0x3bdd>
   9c8df:	movslq %r11d,%r11
   9c8e2:	mov    %rdi,%rbx
   9c8e5:	lea    0x7(%r9),%ecx
   9c8e9:	movzbl (%r14,%r11,1),%r11d
   9c8ee:	sub    %rdx,%rbx
   9c8f1:	cmp    $0x7,%rsi
   9c8f5:	lea    -0x7(%rax),%rdx
   9c8f9:	mov    %r11b,0x0(%r13,%rbx,1)
   9c8fe:	je     9ca1e <__strxfrm_l+0x31ee>
   9c904:	movslq %ecx,%rcx
   9c907:	mov    %rdi,%rbx
   9c90a:	lea    0x8(%r9),%r11d
   9c90e:	movzbl (%r14,%rcx,1),%ecx
   9c913:	sub    %rdx,%rbx
   9c916:	cmp    $0x8,%rsi
   9c91a:	lea    -0x8(%rax),%rdx
   9c91e:	mov    %cl,0x0(%r13,%rbx,1)
   9c923:	je     9d40d <__strxfrm_l+0x3bdd>
   9c929:	movslq %r11d,%r11
   9c92c:	mov    %rdi,%rbx
   9c92f:	lea    0x9(%r9),%ecx
   9c933:	movzbl (%r14,%r11,1),%r11d
   9c938:	sub    %rdx,%rbx
   9c93b:	cmp    $0x9,%rsi
   9c93f:	lea    -0x9(%rax),%rdx
   9c943:	mov    %r11b,0x0(%r13,%rbx,1)
   9c948:	je     9ca1e <__strxfrm_l+0x31ee>
   9c94e:	movslq %ecx,%rcx
   9c951:	mov    %rdi,%rbx
   9c954:	lea    0xa(%r9),%r11d
   9c958:	movzbl (%r14,%rcx,1),%ecx
   9c95d:	sub    %rdx,%rbx
   9c960:	cmp    $0xa,%rsi
   9c964:	lea    -0xa(%rax),%rdx
   9c968:	mov    %cl,0x0(%r13,%rbx,1)
   9c96d:	je     9d40d <__strxfrm_l+0x3bdd>
   9c973:	movslq %r11d,%r11
   9c976:	mov    %rdi,%rbx
   9c979:	lea    0xb(%r9),%ecx
   9c97d:	movzbl (%r14,%r11,1),%r11d
   9c982:	sub    %rdx,%rbx
   9c985:	cmp    $0xb,%rsi
   9c989:	lea    -0xb(%rax),%rdx
   9c98d:	mov    %r11b,0x0(%r13,%rbx,1)
   9c992:	je     9ca1e <__strxfrm_l+0x31ee>
   9c998:	movslq %ecx,%rcx
   9c99b:	mov    %rdi,%rbx
   9c99e:	lea    0xc(%r9),%r11d
   9c9a2:	movzbl (%r14,%rcx,1),%ecx
   9c9a7:	sub    %rdx,%rbx
   9c9aa:	cmp    $0xc,%rsi
   9c9ae:	lea    -0xc(%rax),%rdx
   9c9b2:	mov    %cl,0x0(%r13,%rbx,1)
   9c9b7:	je     9d40d <__strxfrm_l+0x3bdd>
   9c9bd:	movslq %r11d,%r11
   9c9c0:	mov    %rdi,%rbx
   9c9c3:	lea    0xd(%r9),%ecx
   9c9c7:	movzbl (%r14,%r11,1),%r11d
   9c9cc:	sub    %rdx,%rbx
   9c9cf:	cmp    $0xd,%rsi
   9c9d3:	lea    -0xd(%rax),%rdx
   9c9d7:	mov    %r11b,0x0(%r13,%rbx,1)
   9c9dc:	je     9ca1e <__strxfrm_l+0x31ee>
   9c9de:	movslq %ecx,%rcx
   9c9e1:	mov    %rdi,%rbx
   9c9e4:	lea    0xe(%r9),%r11d
   9c9e8:	movzbl (%r14,%rcx,1),%ecx
   9c9ed:	sub    %rdx,%rbx
   9c9f0:	cmp    $0xf,%rsi
   9c9f4:	lea    -0xe(%rax),%rdx
   9c9f8:	mov    %cl,0x0(%r13,%rbx,1)
   9c9fd:	jne    9d40d <__strxfrm_l+0x3bdd>
   9ca03:	movslq %r11d,%r11
   9ca06:	lea    0xf(%r9),%ecx
   9ca0a:	mov    %rdi,%rbx
   9ca0d:	movzbl (%r14,%r11,1),%r9d
   9ca12:	sub    %rdx,%rbx
   9ca15:	lea    -0xf(%rax),%rdx
   9ca19:	mov    %r9b,0x0(%r13,%rbx,1)
   9ca1e:	mov    %rax,%r11
   9ca21:	sub    %rsi,%r10
   9ca24:	sub    %rsi,%r11
   9ca27:	lea    -0x10(%r11),%r9
   9ca2b:	mov    %r11,%rbx
   9ca2e:	shr    $0x4,%r9
   9ca32:	add    $0x1,%r9
   9ca36:	mov    %r9,%r11
   9ca39:	shl    $0x4,%r11
   9ca3d:	cmp    $0xe,%r10
   9ca41:	jbe    9cbaf <__strxfrm_l+0x337f>
   9ca47:	add    %rsi,%r8
   9ca4a:	add    -0x50(%rbp),%rsi
   9ca4e:	add    %r14,%r8
   9ca51:	movdqa (%r8),%xmm0
   9ca56:	add    %r13,%rsi
   9ca59:	cmp    $0x1,%r9
   9ca5d:	movups %xmm0,(%rsi)
   9ca60:	je     9cba0 <__strxfrm_l+0x3370>
   9ca66:	cmp    $0x2,%r9
   9ca6a:	movdqa 0x10(%r8),%xmm0
   9ca70:	movups %xmm0,0x10(%rsi)
   9ca74:	je     9cba0 <__strxfrm_l+0x3370>
   9ca7a:	cmp    $0x3,%r9
   9ca7e:	movdqa 0x20(%r8),%xmm0
   9ca84:	movups %xmm0,0x20(%rsi)
   9ca88:	je     9cba0 <__strxfrm_l+0x3370>
   9ca8e:	cmp    $0x4,%r9
   9ca92:	movdqa 0x30(%r8),%xmm0
   9ca98:	movups %xmm0,0x30(%rsi)
   9ca9c:	je     9cba0 <__strxfrm_l+0x3370>
   9caa2:	cmp    $0x5,%r9
   9caa6:	movdqa 0x40(%r8),%xmm0
   9caac:	movups %xmm0,0x40(%rsi)
   9cab0:	je     9cba0 <__strxfrm_l+0x3370>
   9cab6:	cmp    $0x6,%r9
   9caba:	movdqa 0x50(%r8),%xmm0
   9cac0:	movups %xmm0,0x50(%rsi)
   9cac4:	je     9cba0 <__strxfrm_l+0x3370>
   9caca:	cmp    $0x7,%r9
   9cace:	movdqa 0x60(%r8),%xmm0
   9cad4:	movups %xmm0,0x60(%rsi)
   9cad8:	je     9cba0 <__strxfrm_l+0x3370>
   9cade:	cmp    $0x8,%r9
   9cae2:	movdqa 0x70(%r8),%xmm0
   9cae8:	movups %xmm0,0x70(%rsi)
   9caec:	je     9cba0 <__strxfrm_l+0x3370>
   9caf2:	cmp    $0x9,%r9
   9caf6:	movdqa 0x80(%r8),%xmm0
   9caff:	movups %xmm0,0x80(%rsi)
   9cb06:	je     9cba0 <__strxfrm_l+0x3370>
   9cb0c:	cmp    $0xa,%r9
   9cb10:	movdqa 0x90(%r8),%xmm0
   9cb19:	movups %xmm0,0x90(%rsi)
   9cb20:	je     9cba0 <__strxfrm_l+0x3370>
   9cb22:	cmp    $0xb,%r9
   9cb26:	movdqa 0xa0(%r8),%xmm0
   9cb2f:	movups %xmm0,0xa0(%rsi)
   9cb36:	je     9cba0 <__strxfrm_l+0x3370>
   9cb38:	cmp    $0xc,%r9
   9cb3c:	movdqa 0xb0(%r8),%xmm0
   9cb45:	movups %xmm0,0xb0(%rsi)
   9cb4c:	je     9cba0 <__strxfrm_l+0x3370>
   9cb4e:	cmp    $0xd,%r9
   9cb52:	movdqa 0xc0(%r8),%xmm0
   9cb5b:	movups %xmm0,0xc0(%rsi)
   9cb62:	je     9cba0 <__strxfrm_l+0x3370>
   9cb64:	cmp    $0xe,%r9
   9cb68:	movdqa 0xd0(%r8),%xmm0
   9cb71:	movups %xmm0,0xd0(%rsi)
   9cb78:	je     9cba0 <__strxfrm_l+0x3370>
   9cb7a:	cmp    $0xf,%r9
   9cb7e:	movdqa 0xe0(%r8),%xmm0
   9cb87:	movups %xmm0,0xe0(%rsi)
   9cb8e:	je     9cba0 <__strxfrm_l+0x3370>
   9cb90:	movdqa 0xf0(%r8),%xmm0
   9cb99:	movups %xmm0,0xf0(%rsi)
   9cba0:	sub    %r11,%rdx
   9cba3:	add    %r11d,%ecx
   9cba6:	cmp    %r11,%rbx
   9cba9:	je     9cd9c <__strxfrm_l+0x356c>
   9cbaf:	movslq %ecx,%r9
   9cbb2:	mov    %rdi,%r8
   9cbb5:	lea    0x1(%rcx),%esi
   9cbb8:	movzbl (%r14,%r9,1),%r9d
   9cbbd:	sub    %rdx,%r8
   9cbc0:	mov    %r9b,0x0(%r13,%r8,1)
   9cbc5:	mov    %rdx,%r9
   9cbc8:	sub    $0x1,%r9
   9cbcc:	je     9cd9c <__strxfrm_l+0x356c>
   9cbd2:	movslq %esi,%rsi
   9cbd5:	mov    %rdi,%rbx
   9cbd8:	lea    0x2(%rcx),%r8d
   9cbdc:	movzbl (%r14,%rsi,1),%esi
   9cbe1:	sub    %r9,%rbx
   9cbe4:	mov    %rdx,%r9
   9cbe7:	sub    $0x2,%r9
   9cbeb:	mov    %sil,0x0(%r13,%rbx,1)
   9cbf0:	je     9cd9c <__strxfrm_l+0x356c>
   9cbf6:	movslq %r8d,%r8
   9cbf9:	mov    %rdi,%rbx
   9cbfc:	lea    0x3(%rcx),%esi
   9cbff:	movzbl (%r14,%r8,1),%r8d
   9cc04:	sub    %r9,%rbx
   9cc07:	mov    %rdx,%r9
   9cc0a:	sub    $0x3,%r9
   9cc0e:	mov    %r8b,0x0(%r13,%rbx,1)
   9cc13:	je     9cd9c <__strxfrm_l+0x356c>
   9cc19:	movslq %esi,%rsi
   9cc1c:	mov    %rdi,%rbx
   9cc1f:	lea    0x4(%rcx),%r8d
   9cc23:	movzbl (%r14,%rsi,1),%esi
   9cc28:	sub    %r9,%rbx
   9cc2b:	mov    %rdx,%r9
   9cc2e:	sub    $0x4,%r9
   9cc32:	mov    %sil,0x0(%r13,%rbx,1)
   9cc37:	je     9cd9c <__strxfrm_l+0x356c>
   9cc3d:	movslq %r8d,%r8
   9cc40:	mov    %rdi,%rbx
   9cc43:	lea    0x5(%rcx),%esi
   9cc46:	movzbl (%r14,%r8,1),%r8d
   9cc4b:	sub    %r9,%rbx
   9cc4e:	mov    %rdx,%r9
   9cc51:	sub    $0x5,%r9
   9cc55:	mov    %r8b,0x0(%r13,%rbx,1)
   9cc5a:	je     9cd9c <__strxfrm_l+0x356c>
   9cc60:	movslq %esi,%rsi
   9cc63:	mov    %rdi,%rbx
   9cc66:	lea    0x6(%rcx),%r8d
   9cc6a:	movzbl (%r14,%rsi,1),%esi
   9cc6f:	sub    %r9,%rbx
   9cc72:	mov    %rdx,%r9
   9cc75:	sub    $0x6,%r9
   9cc79:	mov    %sil,0x0(%r13,%rbx,1)
   9cc7e:	je     9cd9c <__strxfrm_l+0x356c>
   9cc84:	movslq %r8d,%r8
   9cc87:	mov    %rdi,%rbx
   9cc8a:	lea    0x7(%rcx),%esi
   9cc8d:	movzbl (%r14,%r8,1),%r8d
   9cc92:	sub    %r9,%rbx
   9cc95:	mov    %rdx,%r9
   9cc98:	sub    $0x7,%r9
   9cc9c:	mov    %r8b,0x0(%r13,%rbx,1)
   9cca1:	je     9cd9c <__strxfrm_l+0x356c>
   9cca7:	movslq %esi,%rsi
   9ccaa:	mov    %rdi,%rbx
   9ccad:	lea    0x8(%rcx),%r8d
   9ccb1:	movzbl (%r14,%rsi,1),%esi
   9ccb6:	sub    %r9,%rbx
   9ccb9:	mov    %rdx,%r9
   9ccbc:	sub    $0x8,%r9
   9ccc0:	mov    %sil,0x0(%r13,%rbx,1)
   9ccc5:	je     9cd9c <__strxfrm_l+0x356c>
   9cccb:	movslq %r8d,%r8
   9ccce:	mov    %rdi,%rbx
   9ccd1:	lea    0x9(%rcx),%esi
   9ccd4:	movzbl (%r14,%r8,1),%r8d
   9ccd9:	sub    %r9,%rbx
   9ccdc:	mov    %rdx,%r9
   9ccdf:	sub    $0x9,%r9
   9cce3:	mov    %r8b,0x0(%r13,%rbx,1)
   9cce8:	je     9cd9c <__strxfrm_l+0x356c>
   9ccee:	movslq %esi,%rsi
   9ccf1:	mov    %rdi,%rbx
   9ccf4:	lea    0xa(%rcx),%r8d
   9ccf8:	movzbl (%r14,%rsi,1),%esi
   9ccfd:	sub    %r9,%rbx
   9cd00:	mov    %rdx,%r9
   9cd03:	sub    $0xa,%r9
   9cd07:	mov    %sil,0x0(%r13,%rbx,1)
   9cd0c:	je     9cd9c <__strxfrm_l+0x356c>
   9cd12:	movslq %r8d,%r8
   9cd15:	mov    %rdi,%rbx
   9cd18:	lea    0xb(%rcx),%esi
   9cd1b:	movzbl (%r14,%r8,1),%r8d
   9cd20:	sub    %r9,%rbx
   9cd23:	mov    %rdx,%r9
   9cd26:	sub    $0xb,%r9
   9cd2a:	mov    %r8b,0x0(%r13,%rbx,1)
   9cd2f:	je     9cd9c <__strxfrm_l+0x356c>
   9cd31:	movslq %esi,%rsi
   9cd34:	mov    %rdi,%rbx
   9cd37:	lea    0xc(%rcx),%r8d
   9cd3b:	movzbl (%r14,%rsi,1),%esi
   9cd40:	sub    %r9,%rbx
   9cd43:	mov    %rdx,%r9
   9cd46:	sub    $0xc,%r9
   9cd4a:	mov    %sil,0x0(%r13,%rbx,1)
   9cd4f:	je     9cd9c <__strxfrm_l+0x356c>
   9cd51:	movslq %r8d,%r8
   9cd54:	mov    %rdi,%rbx
   9cd57:	lea    0xd(%rcx),%esi
   9cd5a:	movzbl (%r14,%r8,1),%r8d
   9cd5f:	sub    %r9,%rbx
   9cd62:	mov    %r8b,0x0(%r13,%rbx,1)
   9cd67:	mov    %rdx,%r8
   9cd6a:	sub    $0xd,%r8
   9cd6e:	je     9cd9c <__strxfrm_l+0x356c>
   9cd70:	movslq %esi,%rsi
   9cd73:	mov    %rdi,%rbx
   9cd76:	add    $0xe,%ecx
   9cd79:	movzbl (%r14,%rsi,1),%esi
   9cd7e:	sub    %r8,%rbx
   9cd81:	sub    $0xe,%rdx
   9cd85:	mov    %sil,0x0(%r13,%rbx,1)
   9cd8a:	je     9cd9c <__strxfrm_l+0x356c>
   9cd8c:	movslq %ecx,%rcx
   9cd8f:	sub    %rdx,%rdi
   9cd92:	movzbl (%r14,%rcx,1),%edx
   9cd97:	mov    %dl,0x0(%r13,%rdi,1)
   9cd9c:	sub    %rax,-0x88(%rbp)
   9cda3:	jne    9c748 <__strxfrm_l+0x2f18>
   9cda9:	mov    -0x60(%rbp),%rdi
   9cdad:	add    %rdi,-0x58(%rbp)
   9cdb1:	jmpq   99f88 <__strxfrm_l+0x758>
   9cdb6:	mov    -0x70(%rbp),%rdx
   9cdba:	sub    %rax,%rdx
   9cdbd:	movslq (%rdx),%rsi
   9cdc0:	lea    0x5(%rdx),%rcx
   9cdc4:	movzbl 0x4(%rdx),%eax
   9cdc8:	test   %esi,%esi
   9cdca:	js     9ce34 <__strxfrm_l+0x3604>
   9cdcc:	test   %rax,%rax
   9cdcf:	je     9cf4c <__strxfrm_l+0x371c>
   9cdd5:	movzbl 0x1(%r12),%ebx
   9cddb:	cmp    %bl,0x5(%rdx)
   9cdde:	jne    9ce08 <__strxfrm_l+0x35d8>
   9cde0:	xor    %edx,%edx
   9cde2:	jmp    9cdf3 <__strxfrm_l+0x35c3>
   9cde4:	nopl   0x0(%rax)
   9cde8:	movzbl 0x1(%r12,%rdx,1),%ebx
   9cdee:	cmp    %bl,(%rcx,%rdx,1)
   9cdf1:	jne    9ce08 <__strxfrm_l+0x35d8>
   9cdf3:	add    $0x1,%rdx
   9cdf7:	cmp    %rdx,%rax
   9cdfa:	jne    9cde8 <__strxfrm_l+0x35b8>
   9cdfc:	lea    (%r15,%rdx,1),%r12
   9ce00:	jmpq   9bb45 <__strxfrm_l+0x2315>
   9ce05:	nopl   (%rax)
   9ce08:	lea    (%rcx,%rax,1),%rdx
   9ce0c:	add    $0x1,%rax
   9ce10:	mov    $0x4,%ecx
   9ce15:	and    $0x3,%eax
   9ce18:	sub    %rax,%rcx
   9ce1b:	add    %rdx,%rcx
   9ce1e:	test   %rax,%rax
   9ce21:	cmovne %rcx,%rdx
   9ce25:	movslq (%rdx),%rsi
   9ce28:	lea    0x5(%rdx),%rcx
   9ce2c:	movzbl 0x4(%rdx),%eax
   9ce30:	test   %esi,%esi
   9ce32:	jns    9cdcc <__strxfrm_l+0x359c>
   9ce34:	test   %rax,%rax
   9ce37:	je     9d378 <__strxfrm_l+0x3b48>
   9ce3d:	movzbl 0x5(%rdx),%ebx
   9ce41:	movzbl 0x1(%r12),%r11d
   9ce47:	cmp    %bl,%r11b
   9ce4a:	jne    9ce7e <__strxfrm_l+0x364e>
   9ce4c:	xor    %edx,%edx
   9ce4e:	jmp    9ce60 <__strxfrm_l+0x3630>
   9ce50:	movzbl (%rcx,%rdx,1),%r9d
   9ce55:	movzbl 0x1(%r12,%rdx,1),%r8d
   9ce5b:	cmp    %r8b,%r9b
   9ce5e:	jne    9ce84 <__strxfrm_l+0x3654>
   9ce60:	add    $0x1,%rdx
   9ce64:	cmp    %rdx,%rax
   9ce67:	jne    9ce50 <__strxfrm_l+0x3620>
   9ce69:	xor    %eax,%eax
   9ce6b:	mov    -0x78(%rbp),%rbx
   9ce6f:	sub    %rsi,%rax
   9ce72:	lea    (%r15,%rdx,1),%r12
   9ce76:	mov    (%rbx,%rax,4),%esi
   9ce79:	jmpq   9bb45 <__strxfrm_l+0x2315>
   9ce7e:	mov    %ebx,%r9d
   9ce81:	mov    %r11d,%r8d
   9ce84:	cmp    %r8b,%r9b
   9ce87:	ja     9cefb <__strxfrm_l+0x36cb>
   9ce89:	lea    (%rcx,%rax,1),%r10
   9ce8d:	movzbl (%r10),%r8d
   9ce91:	cmp    %r8b,%r11b
   9ce94:	jne    9cf14 <__strxfrm_l+0x36e4>
   9ce96:	xor    %edx,%edx
   9ce98:	jmp    9ceb0 <__strxfrm_l+0x3680>
   9ce9a:	nopw   0x0(%rax,%rax,1)
   9cea0:	movzbl (%r10,%rdx,1),%r8d
   9cea5:	movzbl 0x1(%r12,%rdx,1),%r9d
   9ceab:	cmp    %r9b,%r8b
   9ceae:	jne    9cf17 <__strxfrm_l+0x36e7>
   9ceb0:	add    $0x1,%rdx
   9ceb4:	cmp    %rdx,%rax
   9ceb7:	jne    9cea0 <__strxfrm_l+0x3670>
   9ceb9:	xor    %r8d,%r8d
   9cebc:	cmp    %bl,%r11b
   9cebf:	jne    9ced1 <__strxfrm_l+0x36a1>
   9cec1:	add    $0x1,%r8
   9cec5:	movzbl 0x1(%r12,%r8,1),%eax
   9cecb:	cmp    %al,(%rcx,%r8,1)
   9cecf:	je     9cec1 <__strxfrm_l+0x3691>
   9ced1:	xor    %eax,%eax
   9ced3:	shl    $0x8,%rax
   9ced7:	movzbl (%rcx,%r8,1),%r9d
   9cedc:	mov    %rax,%r10
   9cedf:	movzbl 0x1(%r12,%r8,1),%eax
   9cee5:	add    $0x1,%r8
   9cee9:	sub    %r9d,%eax
   9ceec:	cltq   
   9ceee:	add    %r10,%rax
   9cef1:	cmp    %rdx,%r8
   9cef4:	jb     9ced3 <__strxfrm_l+0x36a3>
   9cef6:	jmpq   9ce6b <__strxfrm_l+0x363b>
   9cefb:	add    %rax,%rax
   9cefe:	lea    0x4(%rax),%rdx
   9cf02:	add    $0x1,%rax
   9cf06:	and    $0x3,%eax
   9cf09:	sub    %rax,%rdx
   9cf0c:	add    %rcx,%rdx
   9cf0f:	jmpq   9cdbd <__strxfrm_l+0x358d>
   9cf14:	mov    %r11d,%r9d
   9cf17:	cmp    %r9b,%r8b
   9cf1a:	jb     9cefb <__strxfrm_l+0x36cb>
   9cf1c:	mov    %rax,%rdx
   9cf1f:	jmp    9ceb9 <__strxfrm_l+0x3689>
   9cf21:	mov    %r15d,%edx
   9cf24:	jmpq   9be1a <__strxfrm_l+0x25ea>
   9cf29:	mov    %ebx,%edx
   9cf2b:	jmpq   9be1a <__strxfrm_l+0x25ea>
   9cf30:	test   %r12,%r12
   9cf33:	cmove  %rbx,%r12
   9cf37:	add    %r11,-0x60(%rbp)
   9cf3b:	jmpq   9c712 <__strxfrm_l+0x2ee2>
   9cf40:	mov    %rax,%rcx
   9cf43:	lea    -0x1(%rax),%r11
   9cf47:	jmpq   9be1a <__strxfrm_l+0x25ea>
   9cf4c:	xor    %edx,%edx
   9cf4e:	lea    (%r15,%rdx,1),%r12
   9cf52:	jmpq   9bb45 <__strxfrm_l+0x2315>
   9cf57:	xor    %edx,%edx
   9cf59:	movzbl (%rcx,%rdx,1),%esi
   9cf5d:	mov    %sil,(%r10,%rdx,1)
   9cf61:	add    $0x1,%rdx
   9cf65:	cmp    %rdx,%rax
   9cf68:	jne    9cf59 <__strxfrm_l+0x3729>
   9cf6a:	jmpq   9c197 <__strxfrm_l+0x2967>
   9cf6f:	mov    -0x70(%rbp),%rsi
   9cf73:	sub    %rax,%rsi
   9cf76:	movslq (%rsi),%rcx
   9cf79:	lea    0x5(%rsi),%rdx
   9cf7d:	movzbl 0x4(%rsi),%eax
   9cf81:	test   %ecx,%ecx
   9cf83:	js     9cfec <__strxfrm_l+0x37bc>
   9cf85:	test   %rax,%rax
   9cf88:	je     9d0d5 <__strxfrm_l+0x38a5>
   9cf8e:	movzbl 0x5(%rsi),%edi
   9cf92:	cmp    %dil,0x1(%rbx)
   9cf96:	jne    9cfc0 <__strxfrm_l+0x3790>
   9cf98:	xor    %esi,%esi
   9cf9a:	jmp    9cfab <__strxfrm_l+0x377b>
   9cf9c:	nopl   0x0(%rax)
   9cfa0:	movzbl 0x1(%rbx,%rsi,1),%edi
   9cfa5:	cmp    %dil,(%rdx,%rsi,1)
   9cfa9:	jne    9cfc0 <__strxfrm_l+0x3790>
   9cfab:	add    $0x1,%rsi
   9cfaf:	cmp    %rsi,%rax
   9cfb2:	jne    9cfa0 <__strxfrm_l+0x3770>
   9cfb4:	add    %rsi,-0x88(%rbp)
   9cfbb:	jmpq   9baa1 <__strxfrm_l+0x2271>
   9cfc0:	lea    (%rdx,%rax,1),%rsi
   9cfc4:	add    $0x1,%rax
   9cfc8:	mov    $0x4,%edx
   9cfcd:	and    $0x3,%eax
   9cfd0:	sub    %rax,%rdx
   9cfd3:	add    %rsi,%rdx
   9cfd6:	test   %rax,%rax
   9cfd9:	cmovne %rdx,%rsi
   9cfdd:	movslq (%rsi),%rcx
   9cfe0:	lea    0x5(%rsi),%rdx
   9cfe4:	movzbl 0x4(%rsi),%eax
   9cfe8:	test   %ecx,%ecx
   9cfea:	jns    9cf85 <__strxfrm_l+0x3755>
   9cfec:	test   %rax,%rax
   9cfef:	je     9f889 <__strxfrm_l+0x6059>
   9cff5:	movzbl 0x1(%rbx),%r10d
   9cffa:	movzbl 0x5(%rsi),%r11d
   9cfff:	cmp    %r10b,%r11b
   9d002:	mov    %r10d,%r15d
   9d005:	jne    9d03b <__strxfrm_l+0x380b>
   9d007:	xor    %edi,%edi
   9d009:	jmp    9d01a <__strxfrm_l+0x37ea>
   9d00b:	movzbl (%rdx,%rdi,1),%r8d
   9d010:	movzbl 0x1(%rbx,%rdi,1),%esi
   9d015:	cmp    %sil,%r8b
   9d018:	jne    9d041 <__strxfrm_l+0x3811>
   9d01a:	add    $0x1,%rdi
   9d01e:	cmp    %rdi,%rax
   9d021:	jne    9d00b <__strxfrm_l+0x37db>
   9d023:	xor    %esi,%esi
   9d025:	mov    -0x78(%rbp),%rax
   9d029:	sub    %rcx,%rsi
   9d02c:	add    %rdi,-0x88(%rbp)
   9d033:	mov    (%rax,%rsi,4),%ecx
   9d036:	jmpq   9baa1 <__strxfrm_l+0x2271>
   9d03b:	mov    %r11d,%r8d
   9d03e:	mov    %r10d,%esi
   9d041:	cmp    %sil,%r8b
   9d044:	ja     9d0bc <__strxfrm_l+0x388c>
   9d046:	lea    (%rdx,%rax,1),%rdi
   9d04a:	movzbl (%rdi),%r9d
   9d04e:	cmp    %r10b,%r9b
   9d051:	jne    9d0b4 <__strxfrm_l+0x3884>
   9d053:	xor    %esi,%esi
   9d055:	jmp    9d067 <__strxfrm_l+0x3837>
   9d057:	movzbl (%rdi,%rsi,1),%r8d
   9d05c:	movzbl 0x1(%rbx,%rsi,1),%r10d
   9d062:	cmp    %r10b,%r8b
   9d065:	jne    9d0b7 <__strxfrm_l+0x3887>
   9d067:	add    $0x1,%rsi
   9d06b:	cmp    %rsi,%rax
   9d06e:	jne    9d057 <__strxfrm_l+0x3827>
   9d070:	mov    %r9d,%r15d
   9d073:	xor    %edi,%edi
   9d075:	cmp    %r15b,%r11b
   9d078:	jne    9d089 <__strxfrm_l+0x3859>
   9d07a:	add    $0x1,%rdi
   9d07e:	movzbl 0x1(%rbx,%rdi,1),%esi
   9d083:	cmp    %sil,(%rdx,%rdi,1)
   9d087:	je     9d07a <__strxfrm_l+0x384a>
   9d089:	xor    %esi,%esi
   9d08b:	movzbl 0x1(%rbx,%rdi,1),%r8d
   9d091:	movzbl (%rdx,%rdi,1),%r9d
   9d096:	shl    $0x8,%rsi
   9d09a:	add    $0x1,%rdi
   9d09e:	sub    %r9d,%r8d
   9d0a1:	movslq %r8d,%r8
   9d0a4:	add    %r8,%rsi
   9d0a7:	cmp    %rax,%rdi
   9d0aa:	jb     9d08b <__strxfrm_l+0x385b>
   9d0ac:	mov    %rax,%rdi
   9d0af:	jmpq   9d025 <__strxfrm_l+0x37f5>
   9d0b4:	mov    %r9d,%r8d
   9d0b7:	cmp    %r10b,%r8b
   9d0ba:	jae    9d073 <__strxfrm_l+0x3843>
   9d0bc:	add    %rax,%rax
   9d0bf:	lea    0x4(%rax),%rsi
   9d0c3:	add    $0x1,%rax
   9d0c7:	and    $0x3,%eax
   9d0ca:	sub    %rax,%rsi
   9d0cd:	add    %rdx,%rsi
   9d0d0:	jmpq   9cf76 <__strxfrm_l+0x3746>
   9d0d5:	xor    %esi,%esi
   9d0d7:	jmpq   9cfb4 <__strxfrm_l+0x3784>
   9d0dc:	mov    -0x70(%rbp),%rdx
   9d0e0:	sub    %rax,%rdx
   9d0e3:	movslq (%rdx),%rsi
   9d0e6:	lea    0x5(%rdx),%rcx
   9d0ea:	movzbl 0x4(%rdx),%eax
   9d0ee:	test   %esi,%esi
   9d0f0:	js     9d15c <__strxfrm_l+0x392c>
   9d0f2:	test   %rax,%rax
   9d0f5:	je     9d24c <__strxfrm_l+0x3a1c>
   9d0fb:	movzbl 0x1(%r12),%edi
   9d101:	cmp    %dil,0x5(%rdx)
   9d105:	jne    9d130 <__strxfrm_l+0x3900>
   9d107:	xor    %edx,%edx
   9d109:	jmp    9d11c <__strxfrm_l+0x38ec>
   9d10b:	nopl   0x0(%rax,%rax,1)
   9d110:	movzbl 0x1(%r12,%rdx,1),%edi
   9d116:	cmp    %dil,(%rcx,%rdx,1)
   9d11a:	jne    9d130 <__strxfrm_l+0x3900>
   9d11c:	add    $0x1,%rdx
   9d120:	cmp    %rdx,%rax
   9d123:	jne    9d110 <__strxfrm_l+0x38e0>
   9d125:	lea    (%r11,%rdx,1),%r12
   9d129:	jmpq   9c769 <__strxfrm_l+0x2f39>
   9d12e:	xchg   %ax,%ax
   9d130:	lea    (%rcx,%rax,1),%rdx
   9d134:	add    $0x1,%rax
   9d138:	mov    $0x4,%ecx
   9d13d:	and    $0x3,%eax
   9d140:	sub    %rax,%rcx
   9d143:	add    %rdx,%rcx
   9d146:	test   %rax,%rax
   9d149:	cmovne %rcx,%rdx
   9d14d:	movslq (%rdx),%rsi
   9d150:	lea    0x5(%rdx),%rcx
   9d154:	movzbl 0x4(%rdx),%eax
   9d158:	test   %esi,%esi
   9d15a:	jns    9d0f2 <__strxfrm_l+0x38c2>
   9d15c:	test   %rax,%rax
   9d15f:	je     9d406 <__strxfrm_l+0x3bd6>
   9d165:	movzbl 0x5(%rdx),%edi
   9d169:	mov    %edi,%ebx
   9d16b:	mov    %dil,-0x50(%rbp)
   9d16f:	movzbl 0x1(%r12),%edi
   9d175:	cmp    %dil,%bl
   9d178:	jne    9d1ac <__strxfrm_l+0x397c>
   9d17a:	xor    %edx,%edx
   9d17c:	jmp    9d18e <__strxfrm_l+0x395e>
   9d17e:	movzbl (%rcx,%rdx,1),%r9d
   9d183:	movzbl 0x1(%r12,%rdx,1),%r8d
   9d189:	cmp    %r8b,%r9b
   9d18c:	jne    9d1b2 <__strxfrm_l+0x3982>
   9d18e:	add    $0x1,%rdx
   9d192:	cmp    %rdx,%rax
   9d195:	jne    9d17e <__strxfrm_l+0x394e>
   9d197:	xor    %eax,%eax
   9d199:	mov    -0x78(%rbp),%rdi
   9d19d:	sub    %rsi,%rax
   9d1a0:	lea    (%r11,%rdx,1),%r12
   9d1a4:	mov    (%rdi,%rax,4),%esi
   9d1a7:	jmpq   9c769 <__strxfrm_l+0x2f39>
   9d1ac:	mov    %ebx,%r9d
   9d1af:	mov    %edi,%r8d
   9d1b2:	cmp    %r8b,%r9b
   9d1b5:	ja     9d220 <__strxfrm_l+0x39f0>
   9d1b7:	lea    (%rcx,%rax,1),%rbx
   9d1bb:	movzbl (%rbx),%r10d
   9d1bf:	cmp    %dil,%r10b
   9d1c2:	jne    9d239 <__strxfrm_l+0x3a09>
   9d1c4:	xor    %edx,%edx
   9d1c6:	jmp    9d1d8 <__strxfrm_l+0x39a8>
   9d1c8:	movzbl (%rbx,%rdx,1),%r9d
   9d1cd:	movzbl 0x1(%r12,%rdx,1),%r8d
   9d1d3:	cmp    %r8b,%r9b
   9d1d6:	jne    9d23f <__strxfrm_l+0x3a0f>
   9d1d8:	add    $0x1,%rdx
   9d1dc:	cmp    %rdx,%rax
   9d1df:	jne    9d1c8 <__strxfrm_l+0x3998>
   9d1e1:	xor    %edi,%edi
   9d1e3:	cmp    %r10b,-0x50(%rbp)
   9d1e7:	jne    9d1f8 <__strxfrm_l+0x39c8>
   9d1e9:	add    $0x1,%rdi
   9d1ed:	movzbl 0x1(%r12,%rdi,1),%eax
   9d1f3:	cmp    %al,(%rcx,%rdi,1)
   9d1f6:	je     9d1e9 <__strxfrm_l+0x39b9>
   9d1f8:	xor    %eax,%eax
   9d1fa:	movzbl 0x1(%r12,%rdi,1),%r8d
   9d200:	movzbl (%rcx,%rdi,1),%r9d
   9d205:	shl    $0x8,%rax
   9d209:	add    $0x1,%rdi
   9d20d:	sub    %r9d,%r8d
   9d210:	movslq %r8d,%r8
   9d213:	add    %r8,%rax
   9d216:	cmp    %rdx,%rdi
   9d219:	jb     9d1fa <__strxfrm_l+0x39ca>
   9d21b:	jmpq   9d199 <__strxfrm_l+0x3969>
   9d220:	add    %rax,%rax
   9d223:	lea    0x4(%rax),%rdx
   9d227:	add    $0x1,%rax
   9d22b:	and    $0x3,%eax
   9d22e:	sub    %rax,%rdx
   9d231:	add    %rcx,%rdx
   9d234:	jmpq   9d0e3 <__strxfrm_l+0x38b3>
   9d239:	mov    %edi,%r8d
   9d23c:	mov    %r10d,%r9d
   9d23f:	cmp    %r8b,%r9b
   9d242:	jb     9d220 <__strxfrm_l+0x39f0>
   9d244:	mov    %rax,%rdx
   9d247:	mov    %edi,%r10d
   9d24a:	jmp    9d1e1 <__strxfrm_l+0x39b1>
   9d24c:	xor    %edx,%edx
   9d24e:	jmpq   9d125 <__strxfrm_l+0x38f5>
   9d253:	mov    %r9d,%ecx
   9d256:	mov    %rax,%rdx
   9d259:	lea    -0x1(%rax),%r10
   9d25d:	jmpq   9ca1e <__strxfrm_l+0x31ee>
   9d262:	xor    %ecx,%ecx
   9d264:	movzbl (%rdx,%rcx,1),%esi
   9d268:	mov    %sil,(%r10,%rcx,1)
   9d26c:	add    $0x1,%rcx
   9d270:	cmp    %rcx,%rax
   9d273:	jne    9d264 <__strxfrm_l+0x3a34>
   9d275:	jmpq   9cd9c <__strxfrm_l+0x356c>
   9d27a:	mov    -0x70(%rbp),%rcx
   9d27e:	mov    -0x90(%rbp),%rsi
   9d285:	sub    %rdx,%rcx
   9d288:	movslq (%rcx),%r10
   9d28b:	lea    0x5(%rcx),%rdi
   9d28f:	movzbl 0x4(%rcx),%edx
   9d293:	test   %r10d,%r10d
   9d296:	js     9d2f0 <__strxfrm_l+0x3ac0>
   9d298:	test   %rdx,%rdx
   9d29b:	je     99b82 <__strxfrm_l+0x352>
   9d2a1:	movzbl 0x5(%rcx),%ebx
   9d2a5:	cmp    %bl,0x1(%rsi)
   9d2a8:	jne    9d2c3 <__strxfrm_l+0x3a93>
   9d2aa:	xor    %ecx,%ecx
   9d2ac:	add    $0x1,%rcx
   9d2b0:	cmp    %rcx,%rdx
   9d2b3:	je     99b82 <__strxfrm_l+0x352>
   9d2b9:	movzbl 0x1(%rsi,%rcx,1),%ebx
   9d2be:	cmp    %bl,(%rdi,%rcx,1)
   9d2c1:	je     9d2ac <__strxfrm_l+0x3a7c>
   9d2c3:	lea    (%rdi,%rdx,1),%rcx
   9d2c7:	add    $0x1,%rdx
   9d2cb:	mov    $0x4,%edi
   9d2d0:	and    $0x3,%edx
   9d2d3:	sub    %rdx,%rdi
   9d2d6:	add    %rcx,%rdi
   9d2d9:	test   %rdx,%rdx
   9d2dc:	cmovne %rdi,%rcx
   9d2e0:	movslq (%rcx),%r10
   9d2e3:	lea    0x5(%rcx),%rdi
   9d2e7:	movzbl 0x4(%rcx),%edx
   9d2eb:	test   %r10d,%r10d
   9d2ee:	jns    9d298 <__strxfrm_l+0x3a68>
   9d2f0:	test   %rdx,%rdx
   9d2f3:	je     9d322 <__strxfrm_l+0x3af2>
   9d2f5:	movzbl 0x5(%rcx),%ebx
   9d2f9:	movzbl 0x1(%rsi),%r11d
   9d2fe:	cmp    %bl,%r11b
   9d301:	jne    9d332 <__strxfrm_l+0x3b02>
   9d303:	xor    %ecx,%ecx
   9d305:	jmp    9d317 <__strxfrm_l+0x3ae7>
   9d307:	movzbl (%rdi,%rcx,1),%r9d
   9d30c:	movzbl 0x1(%rsi,%rcx,1),%r8d
   9d312:	cmp    %r8b,%r9b
   9d315:	jne    9d338 <__strxfrm_l+0x3b08>
   9d317:	add    $0x1,%rcx
   9d31b:	cmp    %rcx,%rdx
   9d31e:	jne    9d307 <__strxfrm_l+0x3ad7>
   9d320:	xor    %edx,%edx
   9d322:	mov    -0x78(%rbp),%rdi
   9d326:	sub    %r10,%rdx
   9d329:	mov    (%rdi,%rdx,4),%r10d
   9d32d:	jmpq   99b82 <__strxfrm_l+0x352>
   9d332:	mov    %ebx,%r9d
   9d335:	mov    %r11d,%r8d
   9d338:	cmp    %r8b,%r9b
   9d33b:	jbe    9d37f <__strxfrm_l+0x3b4f>
   9d33d:	add    %rdx,%rdx
   9d340:	lea    0x4(%rdx),%rcx
   9d344:	add    $0x1,%rdx
   9d348:	and    $0x3,%edx
   9d34b:	sub    %rdx,%rcx
   9d34e:	add    %rdi,%rcx
   9d351:	jmpq   9d288 <__strxfrm_l+0x3a58>
   9d356:	mov    -0x58(%rbp),%rdx
   9d35a:	jmpq   9c1bf <__strxfrm_l+0x298f>
   9d35f:	xor    %edx,%edx
   9d361:	jmpq   9a944 <__strxfrm_l+0x1114>
   9d366:	xor    %ecx,%ecx
   9d368:	jmpq   9a232 <__strxfrm_l+0xa02>
   9d36d:	mov    %r10,%rdi
   9d370:	mov    %rdx,%rsi
   9d373:	jmpq   9c41b <__strxfrm_l+0x2beb>
   9d378:	xor    %edx,%edx
   9d37a:	jmpq   9ce6b <__strxfrm_l+0x363b>
   9d37f:	lea    (%rdi,%rdx,1),%r12
   9d383:	movzbl (%r12),%ecx
   9d388:	cmp    %cl,%r11b
   9d38b:	jne    9d3f5 <__strxfrm_l+0x3bc5>
   9d38d:	xor    %r8d,%r8d
   9d390:	jmp    9d3a2 <__strxfrm_l+0x3b72>
   9d392:	movzbl (%r12,%r8,1),%ecx
   9d397:	movzbl 0x1(%rsi,%r8,1),%r9d
   9d39d:	cmp    %r9b,%cl
   9d3a0:	jne    9d3f8 <__strxfrm_l+0x3bc8>
   9d3a2:	add    $0x1,%r8
   9d3a6:	cmp    %r8,%rdx
   9d3a9:	jne    9d392 <__strxfrm_l+0x3b62>
   9d3ab:	xor    %ecx,%ecx
   9d3ad:	cmp    %bl,%r11b
   9d3b0:	jne    9d3c7 <__strxfrm_l+0x3b97>
   9d3b2:	mov    -0x90(%rbp),%rbx
   9d3b9:	add    $0x1,%rcx
   9d3bd:	movzbl 0x1(%rbx,%rcx,1),%ebx
   9d3c2:	cmp    %bl,(%rdi,%rcx,1)
   9d3c5:	je     9d3b2 <__strxfrm_l+0x3b82>
   9d3c7:	mov    -0x90(%rbp),%rbx
   9d3ce:	xor    %edx,%edx
   9d3d0:	movzbl 0x1(%rbx,%rcx,1),%esi
   9d3d5:	movzbl (%rdi,%rcx,1),%r9d
   9d3da:	shl    $0x8,%rdx
   9d3de:	add    $0x1,%rcx
   9d3e2:	sub    %r9d,%esi
   9d3e5:	movslq %esi,%rsi
   9d3e8:	add    %rsi,%rdx
   9d3eb:	cmp    %r8,%rcx
   9d3ee:	jb     9d3d0 <__strxfrm_l+0x3ba0>
   9d3f0:	jmpq   9d322 <__strxfrm_l+0x3af2>
   9d3f5:	mov    %r11d,%r9d
   9d3f8:	cmp    %r9b,%cl
   9d3fb:	jb     9d33d <__strxfrm_l+0x3b0d>
   9d401:	mov    %rdx,%r8
   9d404:	jmp    9d3ab <__strxfrm_l+0x3b7b>
   9d406:	xor    %edx,%edx
   9d408:	jmpq   9d199 <__strxfrm_l+0x3969>
   9d40d:	mov    %r11d,%ecx
   9d410:	jmpq   9ca1e <__strxfrm_l+0x31ee>
   9d415:	xor    %edx,%edx
   9d417:	jmpq   9a9b7 <__strxfrm_l+0x1187>
   9d41c:	xor    %ecx,%ecx
   9d41e:	jmpq   9b2db <__strxfrm_l+0x1aab>
   9d423:	xor    %eax,%eax
   9d425:	movzbl (%r8,%rax,1),%edx
   9d42a:	mov    %dl,(%r10,%rax,1)
   9d42e:	add    $0x1,%rax
   9d432:	cmp    %rax,-0x88(%rbp)
   9d439:	jne    9d425 <__strxfrm_l+0x3bf5>
   9d43b:	jmpq   99e10 <__strxfrm_l+0x5e0>
   9d440:	mov    %eax,%edi
   9d442:	and    $0x3f,%eax
   9d445:	movb   $0xc0,-0x40(%rbp)
   9d449:	or     $0xffffff80,%eax
   9d44c:	mov    %al,-0x3f(%rbp)
   9d44f:	mov    %edi,%eax
   9d451:	mov    $0x2,%edi
   9d456:	sar    $0x6,%eax
   9d459:	jmpq   9ab2c <__strxfrm_l+0x12fc>
   9d45e:	xor    %edx,%edx
   9d460:	movzbl (%rbx,%rdx,1),%ecx
   9d464:	mov    %cl,(%r9,%rdx,1)
   9d468:	add    $0x1,%rdx
   9d46c:	cmp    %rdx,%rax
   9d46f:	jne    9d460 <__strxfrm_l+0x3c30>
   9d471:	jmpq   99f6b <__strxfrm_l+0x73b>
   9d476:	mov    $0x4,%r11d
   9d47c:	mov    $0x3,%esi
   9d481:	mov    $0xfffffff0,%ecx
   9d486:	mov    %edi,%ebx
   9d488:	jmpq   9b3e4 <__strxfrm_l+0x1bb4>
   9d48d:	mov    $0x4,%r9d
   9d493:	mov    $0x3,%esi
   9d498:	mov    $0xfffffff0,%ecx
   9d49d:	mov    %edi,%ebx
   9d49f:	jmpq   9a33f <__strxfrm_l+0xb0f>
   9d4a4:	mov    $0x3,%r9d
   9d4aa:	mov    $0x2,%esi
   9d4af:	mov    $0xffffffe0,%ecx
   9d4b4:	mov    %edi,%ebx
   9d4b6:	jmpq   9a33f <__strxfrm_l+0xb0f>
   9d4bb:	mov    $0x3,%r11d
   9d4c1:	mov    $0x2,%esi
   9d4c6:	mov    $0xffffffe0,%ecx
   9d4cb:	mov    %edi,%ebx
   9d4cd:	jmpq   9b3e4 <__strxfrm_l+0x1bb4>
   9d4d2:	mov    %edi,%ecx
   9d4d4:	movb   $0xc0,-0x40(%rbp)
   9d4d8:	mov    $0x2,%r11d
   9d4de:	and    $0x3f,%ecx
   9d4e1:	or     $0xffffff80,%ecx
   9d4e4:	mov    %cl,-0x3f(%rbp)
   9d4e7:	mov    %edi,%ecx
   9d4e9:	sar    $0x6,%ecx
   9d4ec:	jmpq   9b455 <__strxfrm_l+0x1c25>
   9d4f1:	mov    $0xe,%esi
   9d4f6:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d4fb:	mov    $0xd,%esi
   9d500:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d505:	mov    $0xc,%esi
   9d50a:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d50f:	mov    $0xb,%esi
   9d514:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d519:	mov    $0xa,%esi
   9d51e:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d523:	mov    $0x9,%esi
   9d528:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d52d:	mov    $0x8,%esi
   9d532:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d537:	mov    $0x7,%esi
   9d53c:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d541:	mov    $0x6,%esi
   9d546:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d54b:	mov    $0x5,%esi
   9d550:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d555:	mov    $0x4,%esi
   9d55a:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d55f:	mov    $0x3,%esi
   9d564:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d569:	mov    $0x2,%esi
   9d56e:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d573:	mov    $0x1,%esi
   9d578:	jmpq   9b63c <__strxfrm_l+0x1e0c>
   9d57d:	mov    $0x4,%edi
   9d582:	mov    $0x3,%edx
   9d587:	mov    $0xfffffff0,%eax
   9d58c:	jmpq   9aab8 <__strxfrm_l+0x1288>
   9d591:	mov    $0x3,%edi
   9d596:	mov    $0x2,%edx
   9d59b:	mov    $0xffffffe0,%eax
   9d5a0:	jmpq   9aab8 <__strxfrm_l+0x1288>
   9d5a5:	mov    $0xe,%edx
   9d5aa:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d5af:	mov    $0xd,%edx
   9d5b4:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d5b9:	mov    $0xc,%edx
   9d5be:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d5c3:	mov    $0xb,%edx
   9d5c8:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d5cd:	mov    $0xa,%edx
   9d5d2:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d5d7:	mov    $0x9,%edx
   9d5dc:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d5e1:	mov    $0x8,%edx
   9d5e6:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d5eb:	mov    $0x7,%edx
   9d5f0:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d5f5:	mov    $0x6,%edx
   9d5fa:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d5ff:	mov    $0x5,%edx
   9d604:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d609:	mov    $0x4,%edx
   9d60e:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d613:	mov    $0x3,%edx
   9d618:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d61d:	mov    $0x2,%edx
   9d622:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d627:	mov    $0x1,%edx
   9d62c:	jmpq   9ad20 <__strxfrm_l+0x14f0>
   9d631:	mov    -0x50(%rbp),%rdi
   9d635:	mov    %rax,-0x90(%rbp)
   9d63c:	mov    %r15,%r13
   9d63f:	movb   $0x0,(%rsi,%rax,1)
   9d643:	movq   $0x1,-0x88(%rbp)
   9d64e:	movq   $0x0,-0x78(%rbp)
   9d656:	lea    -0x4(%rdi,%rbx,4),%rbx
   9d65b:	lea    -0x4(%rdi,%rax,4),%rax
   9d660:	mov    %rbx,-0xe0(%rbp)
   9d667:	mov    %rax,-0xe8(%rbp)
   9d66e:	lea    -0x4(%rdi),%rax
   9d672:	mov    -0x88(%rbp),%rbx
   9d679:	mov    %rax,-0xa8(%rbp)
   9d680:	mov    -0x58(%rbp),%rax
   9d684:	mov    -0xb8(%rbp),%rdi
   9d68b:	movzbl (%rax),%eax
   9d68e:	lea    -0x1(%rdi,%rbx,1),%rdi
   9d693:	imul   -0x80(%rbp),%rax
   9d698:	mov    %rdi,-0xb0(%rbp)
   9d69f:	movzbl (%rdi,%rax,1),%eax
   9d6a3:	mov    %eax,%edx
   9d6a5:	and    $0x4,%edx
   9d6a8:	jne    9e5f0 <__strxfrm_l+0x4dc0>
   9d6ae:	mov    -0xa8(%rbp),%r9
   9d6b5:	mov    -0x78(%rbp),%r15
   9d6b9:	mov    $0xffffffffffffffff,%rcx
   9d6c0:	movq   $0x0,-0x70(%rbp)
   9d6c8:	mov    %r13,%rbx
   9d6cb:	mov    %r9,-0x48(%rbp)
   9d6cf:	test   $0x1,%al
   9d6d1:	je     9e558 <__strxfrm_l+0x4d28>
   9d6d7:	cmp    $0xffffffffffffffff,%rcx
   9d6db:	je     9dbbb <__strxfrm_l+0x438b>
   9d6e1:	cmp    -0x70(%rbp),%rcx
   9d6e5:	jae    9dbbb <__strxfrm_l+0x438b>
   9d6eb:	mov    -0x50(%rbp),%rax
   9d6ef:	mov    -0x48(%rbp),%r11
   9d6f3:	lea    -0x4(%rax,%rcx,4),%rax
   9d6f8:	mov    %rax,-0xc0(%rbp)
   9d6ff:	jmp    9d71a <__strxfrm_l+0x3eea>
   9d701:	add    %edx,%eax
   9d703:	mov    %r8,%r15
   9d706:	mov    %eax,(%r11)
   9d709:	sub    $0x4,%r11
   9d70d:	cmp    %r11,-0xc0(%rbp)
   9d714:	je     9dbbb <__strxfrm_l+0x438b>
   9d71a:	movslq (%r11),%r12
   9d71d:	movzbl (%r14,%r12,1),%edx
   9d722:	lea    0x1(%r12),%eax
   9d727:	mov    %r12,%rcx
   9d72a:	mov    %eax,(%r11)
   9d72d:	lea    (%rdx,%r15,1),%r8
   9d731:	cmp    %r8,-0x68(%rbp)
   9d735:	jbe    9d701 <__strxfrm_l+0x3ed1>
   9d737:	test   %rdx,%rdx
   9d73a:	lea    -0x1(%rdx),%r9
   9d73e:	je     9d709 <__strxfrm_l+0x3ed9>
   9d740:	lea    0x1(%r12),%rsi
   9d745:	lea    (%rbx,%r15,1),%r10
   9d749:	lea    0x11(%r14,%r12,1),%r12
   9d74e:	lea    (%r14,%rsi,1),%r13
   9d752:	mov    %r13,-0x98(%rbp)
   9d759:	lea    0x10(%rbx,%r15,1),%r13
   9d75e:	cmp    %r13,-0x98(%rbp)
   9d765:	setae  %r13b
   9d769:	cmp    %r12,%r10
   9d76c:	setae  %r12b
   9d770:	or     %r12b,%r13b
   9d773:	je     9e52e <__strxfrm_l+0x4cfe>
   9d779:	cmp    $0x14,%dl
   9d77c:	jbe    9e52e <__strxfrm_l+0x4cfe>
   9d782:	lea    (%r14,%rsi,1),%r12
   9d786:	neg    %r12
   9d789:	and    $0xf,%r12d
   9d78d:	cmp    %rdx,%r12
   9d790:	cmova  %rdx,%r12
   9d794:	test   %r12,%r12
   9d797:	je     9e51f <__strxfrm_l+0x4cef>
   9d79d:	cltq   
   9d79f:	cmp    $0x1,%r12
   9d7a3:	lea    0x1(%r15),%rdi
   9d7a7:	movzbl (%r14,%rax,1),%eax
   9d7ac:	lea    0x2(%rcx),%r13d
   9d7b0:	mov    %al,(%r10)
   9d7b3:	lea    -0x2(%rdx),%r10
   9d7b7:	je     9f97d <__strxfrm_l+0x614d>
   9d7bd:	movslq %r13d,%r10
   9d7c0:	cmp    $0x2,%r12
   9d7c4:	lea    0x2(%r15),%rdi
   9d7c8:	movzbl (%r14,%r10,1),%r10d
   9d7cd:	lea    0x3(%rcx),%eax
   9d7d0:	mov    %r10b,0x1(%rbx,%r15,1)
   9d7d5:	lea    -0x3(%rdx),%r10
   9d7d9:	je     9d9d7 <__strxfrm_l+0x41a7>
   9d7df:	cltq   
   9d7e1:	lea    0x4(%rcx),%r10d
   9d7e5:	cmp    $0x3,%r12
   9d7e9:	movzbl (%r14,%rax,1),%eax
   9d7ee:	lea    0x3(%r15),%rdi
   9d7f2:	mov    %r10d,-0x98(%rbp)
   9d7f9:	lea    -0x4(%rdx),%r10
   9d7fd:	mov    %al,0x2(%rbx,%r15,1)
   9d802:	je     9f990 <__strxfrm_l+0x6160>
   9d808:	movslq -0x98(%rbp),%r10
   9d80f:	cmp    $0x4,%r12
   9d813:	lea    0x4(%r15),%rdi
   9d817:	lea    0x5(%rcx),%eax
   9d81a:	movzbl (%r14,%r10,1),%r10d
   9d81f:	mov    %r10b,0x3(%rbx,%r15,1)
   9d824:	lea    -0x5(%rdx),%r10
   9d828:	je     9d9d7 <__strxfrm_l+0x41a7>
   9d82e:	cltq   
   9d830:	lea    0x6(%rcx),%r10d
   9d834:	cmp    $0x5,%r12
   9d838:	movzbl (%r14,%rax,1),%eax
   9d83d:	lea    0x5(%r15),%rdi
   9d841:	mov    %r10d,-0x98(%rbp)
   9d848:	lea    -0x6(%rdx),%r10
   9d84c:	mov    %al,0x4(%rbx,%r15,1)
   9d851:	je     9f990 <__strxfrm_l+0x6160>
   9d857:	movslq -0x98(%rbp),%r10
   9d85e:	cmp    $0x6,%r12
   9d862:	lea    0x6(%r15),%rdi
   9d866:	lea    0x7(%rcx),%eax
   9d869:	movzbl (%r14,%r10,1),%r10d
   9d86e:	mov    %r10b,0x5(%rbx,%r15,1)
   9d873:	lea    -0x7(%rdx),%r10
   9d877:	je     9d9d7 <__strxfrm_l+0x41a7>
   9d87d:	cltq   
   9d87f:	lea    0x8(%rcx),%r10d
   9d883:	cmp    $0x7,%r12
   9d887:	movzbl (%r14,%rax,1),%eax
   9d88c:	lea    0x7(%r15),%rdi
   9d890:	mov    %r10d,-0x98(%rbp)
   9d897:	lea    -0x8(%rdx),%r10
   9d89b:	mov    %al,0x6(%rbx,%r15,1)
   9d8a0:	je     9f990 <__strxfrm_l+0x6160>
   9d8a6:	movslq -0x98(%rbp),%r10
   9d8ad:	cmp    $0x8,%r12
   9d8b1:	lea    0x8(%r15),%rdi
   9d8b5:	lea    0x9(%rcx),%eax
   9d8b8:	movzbl (%r14,%r10,1),%r10d
   9d8bd:	mov    %r10b,0x7(%rbx,%r15,1)
   9d8c2:	lea    -0x9(%rdx),%r10
   9d8c6:	je     9d9d7 <__strxfrm_l+0x41a7>
   9d8cc:	cltq   
   9d8ce:	lea    0xa(%rcx),%r10d
   9d8d2:	cmp    $0x9,%r12
   9d8d6:	movzbl (%r14,%rax,1),%eax
   9d8db:	lea    0x9(%r15),%rdi
   9d8df:	mov    %r10d,-0x98(%rbp)
   9d8e6:	lea    -0xa(%rdx),%r10
   9d8ea:	mov    %al,0x8(%rbx,%r15,1)
   9d8ef:	je     9f990 <__strxfrm_l+0x6160>
   9d8f5:	movslq -0x98(%rbp),%r10
   9d8fc:	cmp    $0xa,%r12
   9d900:	lea    0xa(%r15),%rdi
   9d904:	lea    0xb(%rcx),%eax
   9d907:	movzbl (%r14,%r10,1),%r10d
   9d90c:	mov    %r10b,0x9(%rbx,%r15,1)
   9d911:	lea    -0xb(%rdx),%r10
   9d915:	je     9d9d7 <__strxfrm_l+0x41a7>
   9d91b:	cltq   
   9d91d:	lea    0xc(%rcx),%r10d
   9d921:	cmp    $0xb,%r12
   9d925:	movzbl (%r14,%rax,1),%eax
   9d92a:	lea    0xb(%r15),%rdi
   9d92e:	mov    %r10d,-0x98(%rbp)
   9d935:	lea    -0xc(%rdx),%r10
   9d939:	mov    %al,0xa(%rbx,%r15,1)
   9d93e:	je     9f990 <__strxfrm_l+0x6160>
   9d944:	movslq -0x98(%rbp),%r10
   9d94b:	cmp    $0xc,%r12
   9d94f:	lea    0xc(%r15),%rdi
   9d953:	lea    0xd(%rcx),%eax
   9d956:	movzbl (%r14,%r10,1),%r10d
   9d95b:	mov    %r10b,0xb(%rbx,%r15,1)
   9d960:	lea    -0xd(%rdx),%r10
   9d964:	je     9d9d7 <__strxfrm_l+0x41a7>
   9d966:	cltq   
   9d968:	lea    0xe(%rcx),%r10d
   9d96c:	cmp    $0xd,%r12
   9d970:	movzbl (%r14,%rax,1),%eax
   9d975:	lea    0xd(%r15),%rdi
   9d979:	mov    %r10d,-0x98(%rbp)
   9d980:	lea    -0xe(%rdx),%r10
   9d984:	mov    %al,0xc(%rbx,%r15,1)
   9d989:	je     9f990 <__strxfrm_l+0x6160>
   9d98f:	lea    0xf(%rcx),%eax
   9d992:	cmp    $0xf,%r12
   9d996:	lea    0xe(%r15),%rdi
   9d99a:	lea    -0xf(%rdx),%r10
   9d99e:	mov    %eax,-0xa0(%rbp)
   9d9a4:	movslq -0x98(%rbp),%rax
   9d9ab:	movzbl (%r14,%rax,1),%eax
   9d9b0:	mov    %al,0xd(%rbx,%r15,1)
   9d9b5:	jne    9f985 <__strxfrm_l+0x6155>
   9d9bb:	lea    0x10(%rcx),%eax
   9d9be:	movslq -0xa0(%rbp),%rcx
   9d9c5:	lea    0xf(%r15),%rdi
   9d9c9:	lea    -0x10(%rdx),%r10
   9d9cd:	movzbl (%r14,%rcx,1),%ecx
   9d9d2:	mov    %cl,0xe(%rbx,%r15,1)
   9d9d7:	cmp    %r12,%rdx
   9d9da:	je     9dba1 <__strxfrm_l+0x4371>
   9d9e0:	sub    %r12,%rdx
   9d9e3:	mov    %rdx,-0xa0(%rbp)
   9d9ea:	sub    $0x10,%rdx
   9d9ee:	shr    $0x4,%rdx
   9d9f2:	lea    0x1(%rdx),%rcx
   9d9f6:	mov    %rcx,-0x98(%rbp)
   9d9fd:	shl    $0x4,%rcx
   9da01:	mov    %rcx,%rdx
   9da04:	mov    %r9,%rcx
   9da07:	sub    %r12,%rcx
   9da0a:	cmp    $0xe,%rcx
   9da0e:	jbe    9da52 <__strxfrm_l+0x4222>
   9da10:	lea    (%r12,%rsi,1),%rcx
   9da14:	add    %r12,%r15
   9da17:	xor    %esi,%esi
   9da19:	add    %rbx,%r15
   9da1c:	xor    %r12d,%r12d
   9da1f:	add    %r14,%rcx
   9da22:	movdqa (%rcx,%rsi,1),%xmm0
   9da27:	add    $0x1,%r12
   9da2b:	movups %xmm0,(%r15,%rsi,1)
   9da30:	add    $0x10,%rsi
   9da34:	cmp    %r12,-0x98(%rbp)
   9da3b:	ja     9da22 <__strxfrm_l+0x41f2>
   9da3d:	add    %rdx,%rdi
   9da40:	sub    %rdx,%r10
   9da43:	add    %edx,%eax
   9da45:	cmp    -0xa0(%rbp),%rdx
   9da4c:	je     9dba1 <__strxfrm_l+0x4371>
   9da52:	movslq %eax,%rcx
   9da55:	test   %r10,%r10
   9da58:	lea    0x1(%rax),%edx
   9da5b:	movzbl (%r14,%rcx,1),%ecx
   9da60:	mov    %cl,(%rbx,%rdi,1)
   9da63:	je     9dba1 <__strxfrm_l+0x4371>
   9da69:	movslq %edx,%rdx
   9da6c:	cmp    $0x1,%r10
   9da70:	lea    0x2(%rax),%ecx
   9da73:	movzbl (%r14,%rdx,1),%edx
   9da78:	mov    %dl,0x1(%rbx,%rdi,1)
   9da7c:	je     9dba1 <__strxfrm_l+0x4371>
   9da82:	movslq %ecx,%rcx
   9da85:	cmp    $0x2,%r10
   9da89:	lea    0x3(%rax),%edx
   9da8c:	movzbl (%r14,%rcx,1),%ecx
   9da91:	mov    %cl,0x2(%rbx,%rdi,1)
   9da95:	je     9dba1 <__strxfrm_l+0x4371>
   9da9b:	movslq %edx,%rdx
   9da9e:	cmp    $0x3,%r10
   9daa2:	lea    0x4(%rax),%ecx
   9daa5:	movzbl (%r14,%rdx,1),%edx
   9daaa:	mov    %dl,0x3(%rbx,%rdi,1)
   9daae:	je     9dba1 <__strxfrm_l+0x4371>
   9dab4:	movslq %ecx,%rcx
   9dab7:	cmp    $0x4,%r10
   9dabb:	lea    0x5(%rax),%edx
   9dabe:	movzbl (%r14,%rcx,1),%ecx
   9dac3:	mov    %cl,0x4(%rbx,%rdi,1)
   9dac7:	je     9dba1 <__strxfrm_l+0x4371>
   9dacd:	movslq %edx,%rdx
   9dad0:	cmp    $0x5,%r10
   9dad4:	lea    0x6(%rax),%ecx
   9dad7:	movzbl (%r14,%rdx,1),%edx
   9dadc:	mov    %dl,0x5(%rbx,%rdi,1)
   9dae0:	je     9dba1 <__strxfrm_l+0x4371>
   9dae6:	movslq %ecx,%rcx
   9dae9:	cmp    $0x6,%r10
   9daed:	lea    0x7(%rax),%edx
   9daf0:	movzbl (%r14,%rcx,1),%ecx
   9daf5:	mov    %cl,0x6(%rbx,%rdi,1)
   9daf9:	je     9dba1 <__strxfrm_l+0x4371>
   9daff:	movslq %edx,%rdx
   9db02:	cmp    $0x7,%r10
   9db06:	lea    0x8(%rax),%ecx
   9db09:	movzbl (%r14,%rdx,1),%edx
   9db0e:	mov    %dl,0x7(%rbx,%rdi,1)
   9db12:	je     9dba1 <__strxfrm_l+0x4371>
   9db18:	movslq %ecx,%rcx
   9db1b:	cmp    $0x8,%r10
   9db1f:	lea    0x9(%rax),%edx
   9db22:	movzbl (%r14,%rcx,1),%ecx
   9db27:	mov    %cl,0x8(%rbx,%rdi,1)
   9db2b:	je     9dba1 <__strxfrm_l+0x4371>
   9db2d:	movslq %edx,%rdx
   9db30:	cmp    $0x9,%r10
   9db34:	lea    0xa(%rax),%ecx
   9db37:	movzbl (%r14,%rdx,1),%edx
   9db3c:	mov    %dl,0x9(%rbx,%rdi,1)
   9db40:	je     9dba1 <__strxfrm_l+0x4371>
   9db42:	movslq %ecx,%rcx
   9db45:	cmp    $0xa,%r10
   9db49:	lea    0xb(%rax),%edx
   9db4c:	movzbl (%r14,%rcx,1),%ecx
   9db51:	mov    %cl,0xa(%rbx,%rdi,1)
   9db55:	je     9dba1 <__strxfrm_l+0x4371>
   9db57:	movslq %edx,%rdx
   9db5a:	cmp    $0xb,%r10
   9db5e:	lea    0xc(%rax),%ecx
   9db61:	movzbl (%r14,%rdx,1),%edx
   9db66:	mov    %dl,0xb(%rbx,%rdi,1)
   9db6a:	je     9dba1 <__strxfrm_l+0x4371>
   9db6c:	movslq %ecx,%rcx
   9db6f:	cmp    $0xc,%r10
   9db73:	lea    0xd(%rax),%edx
   9db76:	movzbl (%r14,%rcx,1),%ecx
   9db7b:	mov    %cl,0xc(%rbx,%rdi,1)
   9db7f:	je     9dba1 <__strxfrm_l+0x4371>
   9db81:	movslq %edx,%rdx
   9db84:	add    $0xe,%eax
   9db87:	cmp    $0xd,%r10
   9db8b:	movzbl (%r14,%rdx,1),%edx
   9db90:	mov    %dl,0xd(%rbx,%rdi,1)
   9db94:	je     9dba1 <__strxfrm_l+0x4371>
   9db96:	cltq   
   9db98:	movzbl (%r14,%rax,1),%eax
   9db9d:	mov    %al,0xe(%rbx,%rdi,1)
   9dba1:	add    %r13d,%r9d
   9dba4:	mov    %r8,%r15
   9dba7:	mov    %r9d,(%r11)
   9dbaa:	sub    $0x4,%r11
   9dbae:	cmp    %r11,-0xc0(%rbp)
   9dbb5:	jne    9d71a <__strxfrm_l+0x3eea>
   9dbbb:	mov    -0x48(%rbp),%rdi
   9dbbf:	movslq 0x4(%rdi),%r11
   9dbc3:	movzbl (%r14,%r11,1),%edx
   9dbc8:	lea    0x1(%r11),%eax
   9dbcc:	mov    %r11,%rsi
   9dbcf:	mov    %eax,0x4(%rdi)
   9dbd2:	lea    (%rdx,%r15,1),%rcx
   9dbd6:	cmp    %rcx,-0x68(%rbp)
   9dbda:	mov    %rcx,-0x98(%rbp)
   9dbe1:	jbe    9e597 <__strxfrm_l+0x4d67>
   9dbe7:	test   %rdx,%rdx
   9dbea:	lea    -0x1(%rdx),%r9
   9dbee:	mov    $0xffffffffffffffff,%rcx
   9dbf5:	je     9e003 <__strxfrm_l+0x47d3>
   9dbfb:	lea    0x1(%r11),%rcx
   9dbff:	lea    0x10(%rbx,%r15,1),%r8
   9dc04:	lea    0x11(%r14,%r11,1),%r11
   9dc09:	lea    (%rbx,%r15,1),%r10
   9dc0d:	lea    (%r14,%rcx,1),%r12
   9dc11:	cmp    %r8,%r12
   9dc14:	setae  %r8b
   9dc18:	cmp    %r11,%r10
   9dc1b:	setae  %r11b
   9dc1f:	or     %r11b,%r8b
   9dc22:	je     9f95c <__strxfrm_l+0x612c>
   9dc28:	cmp    $0x14,%dl
   9dc2b:	jbe    9f95c <__strxfrm_l+0x612c>
   9dc31:	mov    %r12,%r11
   9dc34:	neg    %r11
   9dc37:	and    $0xf,%r11d
   9dc3b:	cmp    %rdx,%r11
   9dc3e:	cmova  %rdx,%r11
   9dc42:	test   %r11,%r11
   9dc45:	je     9f94d <__strxfrm_l+0x611d>
   9dc4b:	cltq   
   9dc4d:	cmp    $0x1,%r11
   9dc51:	lea    0x1(%r15),%rdi
   9dc55:	movzbl (%r14,%rax,1),%eax
   9dc5a:	lea    0x2(%rsi),%r8d
   9dc5e:	mov    %al,(%r10)
   9dc61:	lea    -0x2(%rdx),%r10
   9dc65:	je     9f945 <__strxfrm_l+0x6115>
   9dc6b:	movslq %r8d,%r10
   9dc6e:	cmp    $0x2,%r11
   9dc72:	lea    0x2(%r15),%rdi
   9dc76:	movzbl (%r14,%r10,1),%r10d
   9dc7b:	lea    0x3(%rsi),%eax
   9dc7e:	mov    %r10b,0x1(%rbx,%r15,1)
   9dc83:	lea    -0x3(%rdx),%r10
   9dc87:	je     9de34 <__strxfrm_l+0x4604>
   9dc8d:	cltq   
   9dc8f:	cmp    $0x3,%r11
   9dc93:	lea    0x3(%r15),%rdi
   9dc97:	movzbl (%r14,%rax,1),%eax
   9dc9c:	lea    0x4(%rsi),%r12d
   9dca0:	lea    -0x4(%rdx),%r10
   9dca4:	mov    %al,0x2(%rbx,%r15,1)
   9dca9:	je     9f93d <__strxfrm_l+0x610d>
   9dcaf:	movslq %r12d,%r12
   9dcb2:	cmp    $0x4,%r11
   9dcb6:	lea    0x4(%r15),%rdi
   9dcba:	movzbl (%r14,%r12,1),%r10d
   9dcbf:	lea    0x5(%rsi),%eax
   9dcc2:	mov    %r10b,0x3(%rbx,%r15,1)
   9dcc7:	lea    -0x5(%rdx),%r10
   9dccb:	je     9de34 <__strxfrm_l+0x4604>
   9dcd1:	cltq   
   9dcd3:	cmp    $0x5,%r11
   9dcd7:	lea    0x5(%r15),%rdi
   9dcdb:	movzbl (%r14,%rax,1),%eax
   9dce0:	lea    0x6(%rsi),%r12d
   9dce4:	lea    -0x6(%rdx),%r10
   9dce8:	mov    %al,0x4(%rbx,%r15,1)
   9dced:	je     9f93d <__strxfrm_l+0x610d>
   9dcf3:	movslq %r12d,%r12
   9dcf6:	cmp    $0x6,%r11
   9dcfa:	lea    0x6(%r15),%rdi
   9dcfe:	movzbl (%r14,%r12,1),%r10d
   9dd03:	lea    0x7(%rsi),%eax
   9dd06:	mov    %r10b,0x5(%rbx,%r15,1)
   9dd0b:	lea    -0x7(%rdx),%r10
   9dd0f:	je     9de34 <__strxfrm_l+0x4604>
   9dd15:	cltq   
   9dd17:	cmp    $0x7,%r11
   9dd1b:	lea    0x7(%r15),%rdi
   9dd1f:	movzbl (%r14,%rax,1),%eax
   9dd24:	lea    0x8(%rsi),%r12d
   9dd28:	lea    -0x8(%rdx),%r10
   9dd2c:	mov    %al,0x6(%rbx,%r15,1)
   9dd31:	je     9f93d <__strxfrm_l+0x610d>
   9dd37:	movslq %r12d,%r12
   9dd3a:	cmp    $0x8,%r11
   9dd3e:	lea    0x8(%r15),%rdi
   9dd42:	movzbl (%r14,%r12,1),%r10d
   9dd47:	lea    0x9(%rsi),%eax
   9dd4a:	mov    %r10b,0x7(%rbx,%r15,1)
   9dd4f:	lea    -0x9(%rdx),%r10
   9dd53:	je     9de34 <__strxfrm_l+0x4604>
   9dd59:	cltq   
   9dd5b:	cmp    $0x9,%r11
   9dd5f:	lea    0x9(%r15),%rdi
   9dd63:	movzbl (%r14,%rax,1),%eax
   9dd68:	lea    0xa(%rsi),%r12d
   9dd6c:	lea    -0xa(%rdx),%r10
   9dd70:	mov    %al,0x8(%rbx,%r15,1)
   9dd75:	je     9f93d <__strxfrm_l+0x610d>
   9dd7b:	movslq %r12d,%r12
   9dd7e:	cmp    $0xa,%r11
   9dd82:	lea    0xa(%r15),%rdi
   9dd86:	movzbl (%r14,%r12,1),%r10d
   9dd8b:	lea    0xb(%rsi),%eax
   9dd8e:	mov    %r10b,0x9(%rbx,%r15,1)
   9dd93:	lea    -0xb(%rdx),%r10
   9dd97:	je     9de34 <__strxfrm_l+0x4604>
   9dd9d:	cltq   
   9dd9f:	cmp    $0xb,%r11
   9dda3:	lea    0xb(%r15),%rdi
   9dda7:	movzbl (%r14,%rax,1),%eax
   9ddac:	lea    0xc(%rsi),%r12d
   9ddb0:	lea    -0xc(%rdx),%r10
   9ddb4:	mov    %al,0xa(%rbx,%r15,1)
   9ddb9:	je     9f93d <__strxfrm_l+0x610d>
   9ddbf:	movslq %r12d,%r12
   9ddc2:	cmp    $0xc,%r11
   9ddc6:	lea    0xc(%r15),%rdi
   9ddca:	movzbl (%r14,%r12,1),%r10d
   9ddcf:	lea    0xd(%rsi),%eax
   9ddd2:	mov    %r10b,0xb(%rbx,%r15,1)
   9ddd7:	lea    -0xd(%rdx),%r10
   9dddb:	je     9de34 <__strxfrm_l+0x4604>
   9dddd:	cltq   
   9dddf:	cmp    $0xd,%r11
   9dde3:	lea    0xd(%r15),%rdi
   9dde7:	movzbl (%r14,%rax,1),%eax
   9ddec:	lea    0xe(%rsi),%r12d
   9ddf0:	lea    -0xe(%rdx),%r10
   9ddf4:	mov    %al,0xc(%rbx,%r15,1)
   9ddf9:	je     9f93d <__strxfrm_l+0x610d>
   9ddff:	movslq %r12d,%r12
   9de02:	cmp    $0xf,%r11
   9de06:	lea    0xe(%r15),%rdi
   9de0a:	movzbl (%r14,%r12,1),%r10d
   9de0f:	lea    0xf(%rsi),%eax
   9de12:	mov    %r10b,0xd(%rbx,%r15,1)
   9de17:	lea    -0xf(%rdx),%r10
   9de1b:	jne    9de34 <__strxfrm_l+0x4604>
   9de1d:	cltq   
   9de1f:	lea    0xf(%r15),%rdi
   9de23:	lea    -0x10(%rdx),%r10
   9de27:	movzbl (%r14,%rax,1),%eax
   9de2c:	mov    %al,0xe(%rbx,%r15,1)
   9de31:	lea    0x10(%rsi),%eax
   9de34:	cmp    %r11,%rdx
   9de37:	je     9dfea <__strxfrm_l+0x47ba>
   9de3d:	sub    %r11,%rdx
   9de40:	mov    %r9,%rsi
   9de43:	lea    -0x10(%rdx),%r13
   9de47:	mov    %rdx,%r12
   9de4a:	sub    %r11,%rsi
   9de4d:	shr    $0x4,%r13
   9de51:	add    $0x1,%r13
   9de55:	mov    %r13,%rdx
   9de58:	shl    $0x4,%rdx
   9de5c:	cmp    $0xe,%rsi
   9de60:	jbe    9de9b <__strxfrm_l+0x466b>
   9de62:	add    %r11,%rcx
   9de65:	add    %r11,%r15
   9de68:	xor    %esi,%esi
   9de6a:	add    %r14,%rcx
   9de6d:	add    %rbx,%r15
   9de70:	xor    %r11d,%r11d
   9de73:	movdqa (%rcx,%rsi,1),%xmm0
   9de78:	add    $0x1,%r11
   9de7c:	movups %xmm0,(%r15,%rsi,1)
   9de81:	add    $0x10,%rsi
   9de85:	cmp    %r11,%r13
   9de88:	ja     9de73 <__strxfrm_l+0x4643>
   9de8a:	add    %rdx,%rdi
   9de8d:	sub    %rdx,%r10
   9de90:	add    %edx,%eax
   9de92:	cmp    %r12,%rdx
   9de95:	je     9dfea <__strxfrm_l+0x47ba>
   9de9b:	movslq %eax,%rcx
   9de9e:	test   %r10,%r10
   9dea1:	lea    0x1(%rax),%edx
   9dea4:	movzbl (%r14,%rcx,1),%ecx
   9dea9:	mov    %cl,(%rbx,%rdi,1)
   9deac:	je     9dfea <__strxfrm_l+0x47ba>
   9deb2:	movslq %edx,%rdx
   9deb5:	cmp    $0x1,%r10
   9deb9:	lea    0x2(%rax),%ecx
   9debc:	movzbl (%r14,%rdx,1),%edx
   9dec1:	mov    %dl,0x1(%rbx,%rdi,1)
   9dec5:	je     9dfea <__strxfrm_l+0x47ba>
   9decb:	movslq %ecx,%rcx
   9dece:	cmp    $0x2,%r10
   9ded2:	lea    0x3(%rax),%edx
   9ded5:	movzbl (%r14,%rcx,1),%ecx
   9deda:	mov    %cl,0x2(%rbx,%rdi,1)
   9dede:	je     9dfea <__strxfrm_l+0x47ba>
   9dee4:	movslq %edx,%rdx
   9dee7:	cmp    $0x3,%r10
   9deeb:	lea    0x4(%rax),%ecx
   9deee:	movzbl (%r14,%rdx,1),%edx
   9def3:	mov    %dl,0x3(%rbx,%rdi,1)
   9def7:	je     9dfea <__strxfrm_l+0x47ba>
   9defd:	movslq %ecx,%rcx
   9df00:	cmp    $0x4,%r10
   9df04:	lea    0x5(%rax),%edx
   9df07:	movzbl (%r14,%rcx,1),%ecx
   9df0c:	mov    %cl,0x4(%rbx,%rdi,1)
   9df10:	je     9dfea <__strxfrm_l+0x47ba>
   9df16:	movslq %edx,%rdx
   9df19:	cmp    $0x5,%r10
   9df1d:	lea    0x6(%rax),%ecx
   9df20:	movzbl (%r14,%rdx,1),%edx
   9df25:	mov    %dl,0x5(%rbx,%rdi,1)
   9df29:	je     9dfea <__strxfrm_l+0x47ba>
   9df2f:	movslq %ecx,%rcx
   9df32:	cmp    $0x6,%r10
   9df36:	lea    0x7(%rax),%edx
   9df39:	movzbl (%r14,%rcx,1),%ecx
   9df3e:	mov    %cl,0x6(%rbx,%rdi,1)
   9df42:	je     9dfea <__strxfrm_l+0x47ba>
   9df48:	movslq %edx,%rdx
   9df4b:	cmp    $0x7,%r10
   9df4f:	lea    0x8(%rax),%ecx
   9df52:	movzbl (%r14,%rdx,1),%edx
   9df57:	mov    %dl,0x7(%rbx,%rdi,1)
   9df5b:	je     9dfea <__strxfrm_l+0x47ba>
   9df61:	movslq %ecx,%rcx
   9df64:	cmp    $0x8,%r10
   9df68:	lea    0x9(%rax),%edx
   9df6b:	movzbl (%r14,%rcx,1),%ecx
   9df70:	mov    %cl,0x8(%rbx,%rdi,1)
   9df74:	je     9dfea <__strxfrm_l+0x47ba>
   9df76:	movslq %edx,%rdx
   9df79:	cmp    $0x9,%r10
   9df7d:	lea    0xa(%rax),%ecx
   9df80:	movzbl (%r14,%rdx,1),%edx
   9df85:	mov    %dl,0x9(%rbx,%rdi,1)
   9df89:	je     9dfea <__strxfrm_l+0x47ba>
   9df8b:	movslq %ecx,%rcx
   9df8e:	cmp    $0xa,%r10
   9df92:	lea    0xb(%rax),%edx
   9df95:	movzbl (%r14,%rcx,1),%ecx
   9df9a:	mov    %cl,0xa(%rbx,%rdi,1)
   9df9e:	je     9dfea <__strxfrm_l+0x47ba>
   9dfa0:	movslq %edx,%rdx
   9dfa3:	cmp    $0xb,%r10
   9dfa7:	lea    0xc(%rax),%ecx
   9dfaa:	movzbl (%r14,%rdx,1),%edx
   9dfaf:	mov    %dl,0xb(%rbx,%rdi,1)
   9dfb3:	je     9dfea <__strxfrm_l+0x47ba>
   9dfb5:	movslq %ecx,%rcx
   9dfb8:	cmp    $0xc,%r10
   9dfbc:	lea    0xd(%rax),%edx
   9dfbf:	movzbl (%r14,%rcx,1),%ecx
   9dfc4:	mov    %cl,0xc(%rbx,%rdi,1)
   9dfc8:	je     9dfea <__strxfrm_l+0x47ba>
   9dfca:	movslq %edx,%rdx
   9dfcd:	add    $0xe,%eax
   9dfd0:	cmp    $0xd,%r10
   9dfd4:	movzbl (%r14,%rdx,1),%edx
   9dfd9:	mov    %dl,0xd(%rbx,%rdi,1)
   9dfdd:	je     9dfea <__strxfrm_l+0x47ba>
   9dfdf:	cltq   
   9dfe1:	movzbl (%r14,%rax,1),%eax
   9dfe6:	mov    %al,0xe(%rbx,%rdi,1)
   9dfea:	mov    -0x48(%rbp),%rax
   9dfee:	mov    -0x98(%rbp),%r15
   9dff5:	add    %r8d,%r9d
   9dff8:	mov    $0xffffffffffffffff,%rcx
   9dfff:	mov    %r9d,0x4(%rax)
   9e003:	mov    -0x70(%rbp),%rdi
   9e007:	mov    -0x58(%rbp),%rsi
   9e00b:	addq   $0x4,-0x48(%rbp)
   9e010:	movzbl 0x1(%rsi,%rdi,1),%eax
   9e015:	add    $0x1,%rdi
   9e019:	mov    -0xb0(%rbp),%rsi
   9e020:	imul   -0x80(%rbp),%rax
   9e025:	cmp    %rdi,-0x90(%rbp)
   9e02c:	mov    %rdi,-0x70(%rbp)
   9e030:	movzbl (%rsi,%rax,1),%eax
   9e034:	jne    9d6cf <__strxfrm_l+0x3e9f>
   9e03a:	cmp    $0xffffffffffffffff,%rcx
   9e03e:	mov    %rbx,%r13
   9e041:	je     9e4da <__strxfrm_l+0x4caa>
   9e047:	cmp    %rcx,-0x90(%rbp)
   9e04e:	jbe    9e4da <__strxfrm_l+0x4caa>
   9e054:	mov    -0x50(%rbp),%rax
   9e058:	mov    -0xe8(%rbp),%r9
   9e05f:	lea    -0x4(%rax,%rcx,4),%rax
   9e064:	mov    %rax,-0x98(%rbp)
   9e06b:	movslq (%r9),%rbx
   9e06e:	movzbl (%r14,%rbx,1),%edx
   9e073:	lea    0x1(%rbx),%eax
   9e076:	mov    %rbx,%rcx
   9e079:	mov    %eax,(%r9)
   9e07c:	lea    (%rdx,%r15,1),%r8
   9e080:	cmp    %r8,-0x68(%rbp)
   9e084:	jbe    9e566 <__strxfrm_l+0x4d36>
   9e08a:	test   %rdx,%rdx
   9e08d:	lea    -0x1(%rdx),%r10
   9e091:	je     9e4c9 <__strxfrm_l+0x4c99>
   9e097:	lea    0x1(%rbx),%rsi
   9e09b:	lea    0x0(%r13,%r15,1),%r11
   9e0a0:	lea    0x11(%r14,%rbx,1),%rbx
   9e0a5:	lea    (%r14,%rsi,1),%r12
   9e0a9:	mov    %r12,-0x48(%rbp)
   9e0ad:	lea    0x10(%r13,%r15,1),%r12
   9e0b2:	cmp    %r12,-0x48(%rbp)
   9e0b6:	setae  %r12b
   9e0ba:	cmp    %rbx,%r11
   9e0bd:	setae  %bl
   9e0c0:	or     %bl,%r12b
   9e0c3:	je     9f914 <__strxfrm_l+0x60e4>
   9e0c9:	cmp    $0x14,%dl
   9e0cc:	jbe    9f914 <__strxfrm_l+0x60e4>
   9e0d2:	lea    (%r14,%rsi,1),%rbx
   9e0d6:	neg    %rbx
   9e0d9:	and    $0xf,%ebx
   9e0dc:	cmp    %rdx,%rbx
   9e0df:	cmova  %rdx,%rbx
   9e0e3:	test   %rbx,%rbx
   9e0e6:	je     9e588 <__strxfrm_l+0x4d58>
   9e0ec:	cltq   
   9e0ee:	cmp    $0x1,%rbx
   9e0f2:	lea    0x1(%r15),%rdi
   9e0f6:	movzbl (%r14,%rax,1),%eax
   9e0fb:	lea    0x2(%rcx),%r12d
   9e0ff:	mov    %al,(%r11)
   9e102:	lea    -0x2(%rdx),%r11
   9e106:	je     9f8c7 <__strxfrm_l+0x6097>
   9e10c:	movslq %r12d,%r11
   9e10f:	cmp    $0x2,%rbx
   9e113:	lea    0x2(%r15),%rdi
   9e117:	movzbl (%r14,%r11,1),%r11d
   9e11c:	lea    0x3(%rcx),%eax
   9e11f:	mov    %r11b,0x1(%r13,%r15,1)
   9e124:	lea    -0x3(%rdx),%r11
   9e128:	je     9e2f3 <__strxfrm_l+0x4ac3>
   9e12e:	cltq   
   9e130:	lea    0x4(%rcx),%r11d
   9e134:	cmp    $0x3,%rbx
   9e138:	movzbl (%r14,%rax,1),%eax
   9e13d:	lea    0x3(%r15),%rdi
   9e141:	mov    %r11d,-0x48(%rbp)
   9e145:	lea    -0x4(%rdx),%r11
   9e149:	mov    %al,0x2(%r13,%r15,1)
   9e14e:	je     9f935 <__strxfrm_l+0x6105>
   9e154:	movslq -0x48(%rbp),%r11
   9e158:	cmp    $0x4,%rbx
   9e15c:	lea    0x4(%r15),%rdi
   9e160:	lea    0x5(%rcx),%eax
   9e163:	movzbl (%r14,%r11,1),%r11d
   9e168:	mov    %r11b,0x3(%r13,%r15,1)
   9e16d:	lea    -0x5(%rdx),%r11
   9e171:	je     9e2f3 <__strxfrm_l+0x4ac3>
   9e177:	cltq   
   9e179:	lea    0x6(%rcx),%r11d
   9e17d:	cmp    $0x5,%rbx
   9e181:	movzbl (%r14,%rax,1),%eax
   9e186:	lea    0x5(%r15),%rdi
   9e18a:	mov    %r11d,-0x48(%rbp)
   9e18e:	lea    -0x6(%rdx),%r11
   9e192:	mov    %al,0x4(%r13,%r15,1)
   9e197:	je     9f935 <__strxfrm_l+0x6105>
   9e19d:	movslq -0x48(%rbp),%r11
   9e1a1:	cmp    $0x6,%rbx
   9e1a5:	lea    0x6(%r15),%rdi
   9e1a9:	lea    0x7(%rcx),%eax
   9e1ac:	movzbl (%r14,%r11,1),%r11d
   9e1b1:	mov    %r11b,0x5(%r13,%r15,1)
   9e1b6:	lea    -0x7(%rdx),%r11
   9e1ba:	je     9e2f3 <__strxfrm_l+0x4ac3>
   9e1c0:	cltq   
   9e1c2:	lea    0x8(%rcx),%r11d
   9e1c6:	cmp    $0x7,%rbx
   9e1ca:	movzbl (%r14,%rax,1),%eax
   9e1cf:	lea    0x7(%r15),%rdi
   9e1d3:	mov    %r11d,-0x48(%rbp)
   9e1d7:	lea    -0x8(%rdx),%r11
   9e1db:	mov    %al,0x6(%r13,%r15,1)
   9e1e0:	je     9f935 <__strxfrm_l+0x6105>
   9e1e6:	movslq -0x48(%rbp),%r11
   9e1ea:	cmp    $0x8,%rbx
   9e1ee:	lea    0x8(%r15),%rdi
   9e1f2:	lea    0x9(%rcx),%eax
   9e1f5:	movzbl (%r14,%r11,1),%r11d
   9e1fa:	mov    %r11b,0x7(%r13,%r15,1)
   9e1ff:	lea    -0x9(%rdx),%r11
   9e203:	je     9e2f3 <__strxfrm_l+0x4ac3>
   9e209:	cltq   
   9e20b:	lea    0xa(%rcx),%r11d
   9e20f:	cmp    $0x9,%rbx
   9e213:	movzbl (%r14,%rax,1),%eax
   9e218:	lea    0x9(%r15),%rdi
   9e21c:	mov    %r11d,-0x48(%rbp)
   9e220:	lea    -0xa(%rdx),%r11
   9e224:	mov    %al,0x8(%r13,%r15,1)
   9e229:	je     9f935 <__strxfrm_l+0x6105>
   9e22f:	movslq -0x48(%rbp),%r11
   9e233:	cmp    $0xa,%rbx
   9e237:	lea    0xa(%r15),%rdi
   9e23b:	lea    0xb(%rcx),%eax
   9e23e:	movzbl (%r14,%r11,1),%r11d
   9e243:	mov    %r11b,0x9(%r13,%r15,1)
   9e248:	lea    -0xb(%rdx),%r11
   9e24c:	je     9e2f3 <__strxfrm_l+0x4ac3>
   9e252:	cltq   
   9e254:	lea    0xc(%rcx),%r11d
   9e258:	cmp    $0xb,%rbx
   9e25c:	movzbl (%r14,%rax,1),%eax
   9e261:	lea    0xb(%r15),%rdi
   9e265:	mov    %r11d,-0x48(%rbp)
   9e269:	lea    -0xc(%rdx),%r11
   9e26d:	mov    %al,0xa(%r13,%r15,1)
   9e272:	je     9f935 <__strxfrm_l+0x6105>
   9e278:	movslq -0x48(%rbp),%r11
   9e27c:	cmp    $0xc,%rbx
   9e280:	lea    0xc(%r15),%rdi
   9e284:	lea    0xd(%rcx),%eax
   9e287:	movzbl (%r14,%r11,1),%r11d
   9e28c:	mov    %r11b,0xb(%r13,%r15,1)
   9e291:	lea    -0xd(%rdx),%r11
   9e295:	je     9e2f3 <__strxfrm_l+0x4ac3>
   9e297:	cltq   
   9e299:	lea    0xe(%rcx),%r11d
   9e29d:	cmp    $0xd,%rbx
   9e2a1:	movzbl (%r14,%rax,1),%eax
   9e2a6:	lea    0xd(%r15),%rdi
   9e2aa:	mov    %r11d,-0x48(%rbp)
   9e2ae:	lea    -0xe(%rdx),%r11
   9e2b2:	mov    %al,0xc(%r13,%r15,1)
   9e2b7:	je     9f935 <__strxfrm_l+0x6105>
   9e2bd:	movslq -0x48(%rbp),%r11
   9e2c1:	cmp    $0xf,%rbx
   9e2c5:	lea    0xe(%r15),%rdi
   9e2c9:	lea    0xf(%rcx),%eax
   9e2cc:	movzbl (%r14,%r11,1),%r11d
   9e2d1:	mov    %r11b,0xd(%r13,%r15,1)
   9e2d6:	lea    -0xf(%rdx),%r11
   9e2da:	jne    9e2f3 <__strxfrm_l+0x4ac3>
   9e2dc:	cltq   
   9e2de:	lea    0xf(%r15),%rdi
   9e2e2:	lea    -0x10(%rdx),%r11
   9e2e6:	movzbl (%r14,%rax,1),%eax
   9e2eb:	mov    %al,0xe(%r13,%r15,1)
   9e2f0:	lea    0x10(%rcx),%eax
   9e2f3:	cmp    %rbx,%rdx
   9e2f6:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e2fc:	sub    %rbx,%rdx
   9e2ff:	mov    %rdx,-0x70(%rbp)
   9e303:	sub    $0x10,%rdx
   9e307:	shr    $0x4,%rdx
   9e30b:	lea    0x1(%rdx),%rcx
   9e30f:	mov    %rcx,-0x48(%rbp)
   9e313:	shl    $0x4,%rcx
   9e317:	mov    %rcx,%rdx
   9e31a:	mov    %r10,%rcx
   9e31d:	sub    %rbx,%rcx
   9e320:	cmp    $0xe,%rcx
   9e324:	jbe    9e361 <__strxfrm_l+0x4b31>
   9e326:	lea    (%rbx,%rsi,1),%rcx
   9e32a:	add    %rbx,%r15
   9e32d:	xor    %esi,%esi
   9e32f:	add    %r13,%r15
   9e332:	xor    %ebx,%ebx
   9e334:	add    %r14,%rcx
   9e337:	movdqa (%rcx,%rsi,1),%xmm0
   9e33c:	add    $0x1,%rbx
   9e340:	movups %xmm0,(%r15,%rsi,1)
   9e345:	add    $0x10,%rsi
   9e349:	cmp    %rbx,-0x48(%rbp)
   9e34d:	ja     9e337 <__strxfrm_l+0x4b07>
   9e34f:	add    %rdx,%rdi
   9e352:	sub    %rdx,%r11
   9e355:	add    %edx,%eax
   9e357:	cmp    -0x70(%rbp),%rdx
   9e35b:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e361:	movslq %eax,%rcx
   9e364:	test   %r11,%r11
   9e367:	lea    0x1(%rax),%edx
   9e36a:	movzbl (%r14,%rcx,1),%ecx
   9e36f:	mov    %cl,0x0(%r13,%rdi,1)
   9e374:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e37a:	movslq %edx,%rdx
   9e37d:	cmp    $0x1,%r11
   9e381:	lea    0x2(%rax),%ecx
   9e384:	movzbl (%r14,%rdx,1),%edx
   9e389:	mov    %dl,0x1(%r13,%rdi,1)
   9e38e:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e394:	movslq %ecx,%rcx
   9e397:	cmp    $0x2,%r11
   9e39b:	lea    0x3(%rax),%edx
   9e39e:	movzbl (%r14,%rcx,1),%ecx
   9e3a3:	mov    %cl,0x2(%r13,%rdi,1)
   9e3a8:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e3ae:	movslq %edx,%rdx
   9e3b1:	cmp    $0x3,%r11
   9e3b5:	lea    0x4(%rax),%ecx
   9e3b8:	movzbl (%r14,%rdx,1),%edx
   9e3bd:	mov    %dl,0x3(%r13,%rdi,1)
   9e3c2:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e3c8:	movslq %ecx,%rcx
   9e3cb:	cmp    $0x4,%r11
   9e3cf:	lea    0x5(%rax),%edx
   9e3d2:	movzbl (%r14,%rcx,1),%ecx
   9e3d7:	mov    %cl,0x4(%r13,%rdi,1)
   9e3dc:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e3e2:	movslq %edx,%rdx
   9e3e5:	cmp    $0x5,%r11
   9e3e9:	lea    0x6(%rax),%ecx
   9e3ec:	movzbl (%r14,%rdx,1),%edx
   9e3f1:	mov    %dl,0x5(%r13,%rdi,1)
   9e3f6:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e3fc:	movslq %ecx,%rcx
   9e3ff:	cmp    $0x6,%r11
   9e403:	lea    0x7(%rax),%edx
   9e406:	movzbl (%r14,%rcx,1),%ecx
   9e40b:	mov    %cl,0x6(%r13,%rdi,1)
   9e410:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e416:	movslq %edx,%rdx
   9e419:	cmp    $0x7,%r11
   9e41d:	lea    0x8(%rax),%ecx
   9e420:	movzbl (%r14,%rdx,1),%edx
   9e425:	mov    %dl,0x7(%r13,%rdi,1)
   9e42a:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e430:	movslq %ecx,%rcx
   9e433:	cmp    $0x8,%r11
   9e437:	lea    0x9(%rax),%edx
   9e43a:	movzbl (%r14,%rcx,1),%ecx
   9e43f:	mov    %cl,0x8(%r13,%rdi,1)
   9e444:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e446:	movslq %edx,%rdx
   9e449:	cmp    $0x9,%r11
   9e44d:	lea    0xa(%rax),%ecx
   9e450:	movzbl (%r14,%rdx,1),%edx
   9e455:	mov    %dl,0x9(%r13,%rdi,1)
   9e45a:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e45c:	movslq %ecx,%rcx
   9e45f:	cmp    $0xa,%r11
   9e463:	lea    0xb(%rax),%edx
   9e466:	movzbl (%r14,%rcx,1),%ecx
   9e46b:	mov    %cl,0xa(%r13,%rdi,1)
   9e470:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e472:	movslq %edx,%rdx
   9e475:	cmp    $0xb,%r11
   9e479:	lea    0xc(%rax),%ecx
   9e47c:	movzbl (%r14,%rdx,1),%edx
   9e481:	mov    %dl,0xb(%r13,%rdi,1)
   9e486:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e488:	movslq %ecx,%rcx
   9e48b:	cmp    $0xc,%r11
   9e48f:	lea    0xd(%rax),%edx
   9e492:	movzbl (%r14,%rcx,1),%ecx
   9e497:	mov    %cl,0xc(%r13,%rdi,1)
   9e49c:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e49e:	movslq %edx,%rdx
   9e4a1:	add    $0xe,%eax
   9e4a4:	cmp    $0xd,%r11
   9e4a8:	movzbl (%r14,%rdx,1),%edx
   9e4ad:	mov    %dl,0xd(%r13,%rdi,1)
   9e4b2:	je     9e4c0 <__strxfrm_l+0x4c90>
   9e4b4:	cltq   
   9e4b6:	movzbl (%r14,%rax,1),%eax
   9e4bb:	mov    %al,0xe(%r13,%rdi,1)
   9e4c0:	add    %r12d,%r10d
   9e4c3:	mov    %r8,%r15
   9e4c6:	mov    %r10d,(%r9)
   9e4c9:	sub    $0x4,%r9
   9e4cd:	cmp    %r9,-0x98(%rbp)
   9e4d4:	jne    9e06b <__strxfrm_l+0x483b>
   9e4da:	cmp    %r15,-0x68(%rbp)
   9e4de:	jbe    9e5af <__strxfrm_l+0x4d7f>
   9e4e4:	mov    -0x88(%rbp),%rax
   9e4eb:	mov    -0x80(%rbp),%rbx
   9e4ef:	lea    0x1(%r15),%rcx
   9e4f3:	cmp    %rax,%rbx
   9e4f6:	mov    %rax,%rdi
   9e4f9:	seta   0x0(%r13,%r15,1)
   9e4ff:	add    $0x1,%rax
   9e503:	cmp    %rdi,%rbx
   9e506:	jbe    9e5cb <__strxfrm_l+0x4d9b>
   9e50c:	mov    %rax,-0x88(%rbp)
   9e513:	mov    %rcx,-0x78(%rbp)
   9e517:	mov    %rax,%rbx
   9e51a:	jmpq   9d680 <__strxfrm_l+0x3e50>
   9e51f:	mov    %r9,%r10
   9e522:	mov    %r15,%rdi
   9e525:	lea    0x2(%rcx),%r13d
   9e529:	jmpq   9d9e0 <__strxfrm_l+0x41b0>
   9e52e:	cltq   
   9e530:	xor    %esi,%esi
   9e532:	add    %r14,%rax
   9e535:	movzbl (%rax,%rsi,1),%edi
   9e539:	mov    %dil,(%r10,%rsi,1)
   9e53d:	add    $0x1,%rsi
   9e541:	cmp    %rsi,%rdx
   9e544:	jne    9e535 <__strxfrm_l+0x4d05>
   9e546:	lea    0x2(%rcx),%r13d
   9e54a:	mov    %r8,%r15
   9e54d:	add    %r13d,%r9d
   9e550:	mov    %r9d,(%r11)
   9e553:	jmpq   9dbaa <__strxfrm_l+0x437a>
   9e558:	cmp    $0xffffffffffffffff,%rcx
   9e55c:	cmove  -0x70(%rbp),%rcx
   9e561:	jmpq   9e003 <__strxfrm_l+0x47d3>
   9e566:	add    %edx,%eax
   9e568:	sub    $0x4,%r9
   9e56c:	mov    %r8,%r15
   9e56f:	mov    %eax,0x4(%r9)
   9e573:	cmp    %r9,-0x98(%rbp)
   9e57a:	jne    9e06b <__strxfrm_l+0x483b>
   9e580:	jmpq   9e4da <__strxfrm_l+0x4caa>
   9e585:	nopl   (%rax)
   9e588:	mov    %r10,%r11
   9e58b:	mov    %r15,%rdi
   9e58e:	lea    0x2(%rcx),%r12d
   9e592:	jmpq   9e2fc <__strxfrm_l+0x4acc>
   9e597:	mov    -0x48(%rbp),%rdi
   9e59b:	add    %edx,%eax
   9e59d:	mov    %rcx,%r15
   9e5a0:	mov    $0xffffffffffffffff,%rcx
   9e5a7:	mov    %eax,0x4(%rdi)
   9e5aa:	jmpq   9e003 <__strxfrm_l+0x47d3>
   9e5af:	mov    -0x88(%rbp),%rdi
   9e5b6:	lea    0x1(%r15),%rcx
   9e5ba:	mov    %rdi,%rax
   9e5bd:	add    $0x1,%rax
   9e5c1:	cmp    %rdi,-0x80(%rbp)
   9e5c5:	ja     9e50c <__strxfrm_l+0x4cdc>
   9e5cb:	cmp    $0x2,%rcx
   9e5cf:	mov    %r15,%r11
   9e5d2:	jbe    9e5e5 <__strxfrm_l+0x4db5>
   9e5d4:	mov    -0x78(%rbp),%rax
   9e5d8:	add    $0x1,%rax
   9e5dc:	cmp    %rcx,%rax
   9e5df:	je     9f8cf <__strxfrm_l+0x609f>
   9e5e5:	lea    -0x1(%rcx),%r13
   9e5e9:	jmpq   99895 <__strxfrm_l+0x65>
   9e5ee:	xchg   %ax,%ax
   9e5f0:	mov    -0xa8(%rbp),%rdi
   9e5f7:	mov    -0x78(%rbp),%r15
   9e5fb:	mov    $0x1,%r8d
   9e601:	movq   $0x0,-0x48(%rbp)
   9e609:	mov    $0xffffffffffffffff,%rdx
   9e610:	mov    %rdi,-0x70(%rbp)
   9e614:	mov    %r13,%rdi
   9e617:	mov    %r15,%r13
   9e61a:	mov    %rdi,%r15
   9e61d:	and    $0x1,%eax
   9e620:	mov    %eax,-0x98(%rbp)
   9e626:	je     9ec9b <__strxfrm_l+0x546b>
   9e62c:	cmp    $0xffffffffffffffff,%rdx
   9e630:	je     9e6c4 <__strxfrm_l+0x4e94>
   9e636:	cmp    -0x48(%rbp),%rdx
   9e63a:	jae    9e6c4 <__strxfrm_l+0x4e94>
   9e640:	mov    -0x50(%rbp),%rax
   9e644:	mov    -0x70(%rbp),%r11
   9e648:	lea    -0x4(%rax,%rdx,4),%rax
   9e64d:	mov    %rax,-0xd8(%rbp)
   9e654:	jmp    9e69d <__strxfrm_l+0x4e6d>
   9e656:	cmp    $0x7f,%r8d
   9e65a:	jg     9eca9 <__strxfrm_l+0x5479>
   9e660:	lea    0x1(%r13),%rdi
   9e664:	mov    %r8b,-0x40(%rbp)
   9e668:	lea    (%rsi,%rdi,1),%rdx
   9e66c:	cmp    %rdx,-0x68(%rbp)
   9e670:	ja     9f8f0 <__strxfrm_l+0x60c0>
   9e676:	mov    $0x1,%r9d
   9e67c:	add    %rsi,%r13
   9e67f:	add    %r10d,%ebx
   9e682:	sub    $0x4,%r11
   9e686:	mov    %ebx,0x4(%r11)
   9e68a:	add    %r9,%r13
   9e68d:	cmp    %r11,-0xd8(%rbp)
   9e694:	mov    -0x98(%rbp),%r8d
   9e69b:	je     9e6c4 <__strxfrm_l+0x4e94>
   9e69d:	movslq (%r11),%rax
   9e6a0:	movzbl (%r14,%rax,1),%esi
   9e6a5:	lea    0x1(%rax),%ebx
   9e6a8:	mov    %ebx,(%r11)
   9e6ab:	test   %rsi,%rsi
   9e6ae:	mov    %rsi,%r10
   9e6b1:	jne    9e656 <__strxfrm_l+0x4e26>
   9e6b3:	add    $0x1,%r8d
   9e6b7:	sub    $0x4,%r11
   9e6bb:	cmp    %r11,-0xd8(%rbp)
   9e6c2:	jne    9e69d <__strxfrm_l+0x4e6d>
   9e6c4:	mov    -0x70(%rbp),%rax
   9e6c8:	movslq 0x4(%rax),%rcx
   9e6cc:	movzbl (%r14,%rcx,1),%esi
   9e6d1:	lea    0x1(%rcx),%ebx
   9e6d4:	mov    %ebx,0x4(%rax)
   9e6d7:	test   %rsi,%rsi
   9e6da:	mov    %rsi,%r10
   9e6dd:	je     9f208 <__strxfrm_l+0x59d8>
   9e6e3:	cmp    $0x7f,%r8d
   9e6e7:	jg     9f6bf <__strxfrm_l+0x5e8f>
   9e6ed:	lea    0x1(%r13),%rdi
   9e6f1:	mov    %r8b,-0x40(%rbp)
   9e6f5:	lea    (%rsi,%rdi,1),%rax
   9e6f9:	cmp    %rax,-0x68(%rbp)
   9e6fd:	ja     9f2a9 <__strxfrm_l+0x5a79>
   9e703:	mov    $0x1,%r9d
   9e709:	mov    -0x70(%rbp),%rax
   9e70d:	add    %r13,%rsi
   9e710:	mov    -0x98(%rbp),%r8d
   9e717:	add    %r10d,%ebx
   9e71a:	lea    (%r9,%rsi,1),%r13
   9e71e:	mov    $0xffffffffffffffff,%rdx
   9e725:	mov    %ebx,0x4(%rax)
   9e728:	mov    -0x48(%rbp),%rdi
   9e72c:	mov    -0x58(%rbp),%rbx
   9e730:	addq   $0x4,-0x70(%rbp)
   9e735:	movzbl 0x1(%rbx,%rdi,1),%eax
   9e73a:	add    $0x1,%rdi
   9e73e:	mov    -0xb0(%rbp),%rbx
   9e745:	imul   -0x80(%rbp),%rax
   9e74a:	cmp    %rdi,-0x90(%rbp)
   9e751:	mov    %rdi,-0x48(%rbp)
   9e755:	movzbl (%rbx,%rax,1),%eax
   9e759:	jne    9e61d <__strxfrm_l+0x4ded>
   9e75f:	mov    %r15,%rax
   9e762:	cmp    $0xffffffffffffffff,%rdx
   9e766:	mov    %r13,%r15
   9e769:	mov    %rax,%r13
   9e76c:	je     9e4da <__strxfrm_l+0x4caa>
   9e772:	cmp    %rdx,-0x60(%rbp)
   9e776:	jbe    9e4da <__strxfrm_l+0x4caa>
   9e77c:	mov    -0x50(%rbp),%rax
   9e780:	mov    -0xe0(%rbp),%r11
   9e787:	lea    -0x4(%rax,%rdx,4),%rax
   9e78c:	mov    %rax,-0xc0(%rbp)
   9e793:	jmp    9e7dd <__strxfrm_l+0x4fad>
   9e795:	nopl   (%rax)
   9e798:	cmp    $0x7f,%r8d
   9e79c:	jg     9e7f9 <__strxfrm_l+0x4fc9>
   9e79e:	lea    0x1(%r15),%rdi
   9e7a2:	mov    %r8b,-0x40(%rbp)
   9e7a6:	lea    (%rdi,%rsi,1),%rdx
   9e7aa:	cmp    %rdx,-0x68(%rbp)
   9e7ae:	ja     9f299 <__strxfrm_l+0x5a69>
   9e7b4:	mov    $0x1,%r9d
   9e7ba:	add    %rsi,%r15
   9e7bd:	add    %r10d,%ebx
   9e7c0:	mov    $0x1,%r8d
   9e7c6:	add    %r9,%r15
   9e7c9:	mov    %ebx,(%r11)
   9e7cc:	sub    $0x4,%r11
   9e7d0:	cmp    %r11,-0xc0(%rbp)
   9e7d7:	je     9e4da <__strxfrm_l+0x4caa>
   9e7dd:	movslq (%r11),%rax
   9e7e0:	movzbl (%r14,%rax,1),%esi
   9e7e5:	lea    0x1(%rax),%ebx
   9e7e8:	mov    %ebx,(%r11)
   9e7eb:	test   %rsi,%rsi
   9e7ee:	mov    %rsi,%r10
   9e7f1:	jne    9e798 <__strxfrm_l+0x4f68>
   9e7f3:	add    $0x1,%r8d
   9e7f7:	jmp    9e7cc <__strxfrm_l+0x4f9c>
   9e7f9:	test   $0xfffff800,%r8d
   9e800:	je     9f278 <__strxfrm_l+0x5a48>
   9e806:	test   $0xffff0000,%r8d
   9e80d:	je     9f263 <__strxfrm_l+0x5a33>
   9e813:	test   $0xffe00000,%r8d
   9e81a:	je     9f24e <__strxfrm_l+0x5a1e>
   9e820:	mov    %r8d,%edx
   9e823:	and    $0xfc000000,%edx
   9e829:	cmp    $0x1,%edx
   9e82c:	sbb    %r9,%r9
   9e82f:	add    $0x6,%r9
   9e833:	cmp    $0x1,%edx
   9e836:	sbb    %ecx,%ecx
   9e838:	add    $0x5,%ecx
   9e83b:	cmp    $0x1,%edx
   9e83e:	sbb    %edx,%edx
   9e840:	and    $0xfffffffc,%edx
   9e843:	sub    $0x4,%edx
   9e846:	mov    %dl,-0x40(%rbp)
   9e849:	mov    %r8d,%edx
   9e84c:	movslq %ecx,%rdi
   9e84f:	and    $0x3f,%edx
   9e852:	or     $0xffffff80,%edx
   9e855:	mov    %dl,-0x40(%rbp,%rdi,1)
   9e859:	mov    %r8d,%edx
   9e85c:	lea    -0x1(%rcx),%edi
   9e85f:	sar    $0x6,%edx
   9e862:	and    $0x3f,%edx
   9e865:	movslq %edi,%rdi
   9e868:	or     $0xffffff80,%edx
   9e86b:	mov    %dl,-0x40(%rbp,%rdi,1)
   9e86f:	mov    %r8d,%edx
   9e872:	mov    %ecx,%edi
   9e874:	sar    $0xc,%edx
   9e877:	sub    $0x2,%edi
   9e87a:	je     9e8bd <__strxfrm_l+0x508d>
   9e87c:	and    $0x3f,%edx
   9e87f:	movslq %edi,%rdi
   9e882:	or     $0xffffff80,%edx
   9e885:	mov    %dl,-0x40(%rbp,%rdi,1)
   9e889:	mov    %r8d,%edx
   9e88c:	mov    %ecx,%edi
   9e88e:	sar    $0x12,%edx
   9e891:	sub    $0x3,%edi
   9e894:	je     9e8bd <__strxfrm_l+0x508d>
   9e896:	and    $0x3f,%edx
   9e899:	movslq %edi,%rdi
   9e89c:	or     $0xffffff80,%edx
   9e89f:	mov    %dl,-0x40(%rbp,%rdi,1)
   9e8a3:	mov    %r8d,%edx
   9e8a6:	sar    $0x18,%edx
   9e8a9:	cmp    $0x4,%ecx
   9e8ac:	je     9e8bd <__strxfrm_l+0x508d>
   9e8ae:	and    $0x3f,%edx
   9e8b1:	or     $0xffffff80,%edx
   9e8b4:	mov    %dl,-0x3f(%rbp)
   9e8b7:	mov    %r8d,%edx
   9e8ba:	sar    $0x1e,%edx
   9e8bd:	lea    (%r15,%r9,1),%rdi
   9e8c1:	or     -0x40(%rbp),%dl
   9e8c4:	lea    (%rsi,%rdi,1),%rcx
   9e8c8:	cmp    %rcx,-0x68(%rbp)
   9e8cc:	mov    %dl,-0x40(%rbp)
   9e8cf:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9e8d5:	mov    %dl,0x0(%r13,%r15,1)
   9e8da:	movzbl -0x3f(%rbp),%edx
   9e8de:	cmp    $0x2,%r9
   9e8e2:	mov    %dl,0x1(%r13,%r15,1)
   9e8e7:	je     9e925 <__strxfrm_l+0x50f5>
   9e8e9:	movzbl -0x3e(%rbp),%edx
   9e8ed:	cmp    $0x3,%r9
   9e8f1:	mov    %dl,0x2(%r13,%r15,1)
   9e8f6:	je     9e925 <__strxfrm_l+0x50f5>
   9e8f8:	movzbl -0x3d(%rbp),%edx
   9e8fc:	cmp    $0x4,%r9
   9e900:	mov    %dl,0x3(%r13,%r15,1)
   9e905:	je     9e925 <__strxfrm_l+0x50f5>
   9e907:	movzbl -0x3c(%rbp),%edx
   9e90b:	cmp    $0x5,%r9
   9e90f:	mov    %dl,0x4(%r13,%r15,1)
   9e914:	je     9e925 <__strxfrm_l+0x50f5>
   9e916:	movzbl -0x3b(%rbp),%edx
   9e91a:	mov    $0x6,%r9d
   9e920:	mov    %dl,0x5(%r13,%r15,1)
   9e925:	lea    0x1(%rax),%rcx
   9e929:	lea    0x0(%r13,%rdi,1),%r8
   9e92e:	lea    0x11(%r14,%rax,1),%rax
   9e933:	movslq %ebx,%rdx
   9e936:	lea    (%r14,%rcx,1),%r12
   9e93a:	mov    %rcx,-0x48(%rbp)
   9e93e:	lea    0x10(%r13,%rdi,1),%rcx
   9e943:	cmp    %rcx,%r12
   9e946:	setae  %cl
   9e949:	cmp    %rax,%r8
   9e94c:	setae  %al
   9e94f:	or     %al,%cl
   9e951:	je     9fa2e <__strxfrm_l+0x61fe>
   9e957:	cmp    $0x14,%r10b
   9e95b:	jbe    9fa2e <__strxfrm_l+0x61fe>
   9e961:	mov    %r12,%rcx
   9e964:	neg    %rcx
   9e967:	and    $0xf,%ecx
   9e96a:	cmp    %rsi,%rcx
   9e96d:	cmova  %rsi,%rcx
   9e971:	test   %rcx,%rcx
   9e974:	je     9fa27 <__strxfrm_l+0x61f7>
   9e97a:	movzbl (%r14,%rdx,1),%eax
   9e97f:	cmp    $0x1,%rcx
   9e983:	mov    %al,(%r8)
   9e986:	je     9fa1d <__strxfrm_l+0x61ed>
   9e98c:	movzbl 0x1(%r14,%rdx,1),%eax
   9e992:	cmp    $0x2,%rcx
   9e996:	mov    %al,0x1(%r13,%rdi,1)
   9e99b:	je     9fa13 <__strxfrm_l+0x61e3>
   9e9a1:	movzbl 0x2(%r14,%rdx,1),%eax
   9e9a7:	cmp    $0x3,%rcx
   9e9ab:	mov    %al,0x2(%r13,%rdi,1)
   9e9b0:	je     9fa09 <__strxfrm_l+0x61d9>
   9e9b6:	movzbl 0x3(%r14,%rdx,1),%eax
   9e9bc:	cmp    $0x4,%rcx
   9e9c0:	mov    %al,0x3(%r13,%rdi,1)
   9e9c5:	je     9f9ff <__strxfrm_l+0x61cf>
   9e9cb:	movzbl 0x4(%r14,%rdx,1),%eax
   9e9d1:	cmp    $0x5,%rcx
   9e9d5:	mov    %al,0x4(%r13,%rdi,1)
   9e9da:	je     9f9f5 <__strxfrm_l+0x61c5>
   9e9e0:	movzbl 0x5(%r14,%rdx,1),%eax
   9e9e6:	cmp    $0x6,%rcx
   9e9ea:	mov    %al,0x5(%r13,%rdi,1)
   9e9ef:	je     9f9eb <__strxfrm_l+0x61bb>
   9e9f5:	movzbl 0x6(%r14,%rdx,1),%eax
   9e9fb:	cmp    $0x7,%rcx
   9e9ff:	mov    %al,0x6(%r13,%rdi,1)
   9ea04:	je     9f9e1 <__strxfrm_l+0x61b1>
   9ea0a:	movzbl 0x7(%r14,%rdx,1),%eax
   9ea10:	cmp    $0x8,%rcx
   9ea14:	mov    %al,0x7(%r13,%rdi,1)
   9ea19:	je     9f9d7 <__strxfrm_l+0x61a7>
   9ea1f:	movzbl 0x8(%r14,%rdx,1),%eax
   9ea25:	cmp    $0x9,%rcx
   9ea29:	mov    %al,0x8(%r13,%rdi,1)
   9ea2e:	je     9f9cd <__strxfrm_l+0x619d>
   9ea34:	movzbl 0x9(%r14,%rdx,1),%eax
   9ea3a:	cmp    $0xa,%rcx
   9ea3e:	mov    %al,0x9(%r13,%rdi,1)
   9ea43:	je     9f9c3 <__strxfrm_l+0x6193>
   9ea49:	movzbl 0xa(%r14,%rdx,1),%eax
   9ea4f:	cmp    $0xb,%rcx
   9ea53:	mov    %al,0xa(%r13,%rdi,1)
   9ea58:	je     9f9b9 <__strxfrm_l+0x6189>
   9ea5e:	movzbl 0xb(%r14,%rdx,1),%eax
   9ea64:	cmp    $0xc,%rcx
   9ea68:	mov    %al,0xb(%r13,%rdi,1)
   9ea6d:	je     9f9af <__strxfrm_l+0x617f>
   9ea73:	movzbl 0xc(%r14,%rdx,1),%eax
   9ea79:	cmp    $0xd,%rcx
   9ea7d:	mov    %al,0xc(%r13,%rdi,1)
   9ea82:	je     9f9a5 <__strxfrm_l+0x6175>
   9ea88:	movzbl 0xd(%r14,%rdx,1),%eax
   9ea8e:	cmp    $0xf,%rcx
   9ea92:	mov    %al,0xd(%r13,%rdi,1)
   9ea97:	jne    9f99b <__strxfrm_l+0x616b>
   9ea9d:	movzbl 0xe(%r14,%rdx,1),%eax
   9eaa3:	mov    %al,0xe(%r13,%rdi,1)
   9eaa8:	mov    $0xf,%eax
   9eaad:	cmp    %rcx,%rsi
   9eab0:	je     9e7ba <__strxfrm_l+0x4f8a>
   9eab6:	mov    %rsi,%r12
   9eab9:	sub    %rcx,%r12
   9eabc:	mov    %r12,-0xb0(%rbp)
   9eac3:	sub    $0x10,%r12
   9eac7:	shr    $0x4,%r12
   9eacb:	add    $0x1,%r12
   9eacf:	mov    %r12,-0xa0(%rbp)
   9ead6:	shl    $0x4,%r12
   9eada:	mov    %r12,-0x98(%rbp)
   9eae1:	lea    -0x1(%rsi),%r12
   9eae5:	sub    %rcx,%r12
   9eae8:	cmp    $0xe,%r12
   9eaec:	jbe    9eb47 <__strxfrm_l+0x5317>
   9eaee:	mov    -0x48(%rbp),%r12
   9eaf2:	add    %rcx,%r12
   9eaf5:	add    %rdi,%rcx
   9eaf8:	lea    0x0(%r13,%rcx,1),%rdi
   9eafd:	add    %r14,%r12
   9eb00:	xor    %ecx,%ecx
   9eb02:	mov    %r12,-0x70(%rbp)
   9eb06:	mov    %rdi,-0x48(%rbp)
   9eb0a:	xor    %edi,%edi
   9eb0c:	mov    -0x70(%rbp),%r12
   9eb10:	add    $0x1,%rdi
   9eb14:	movdqa (%r12,%rcx,1),%xmm0
   9eb1a:	mov    -0x48(%rbp),%r12
   9eb1e:	movups %xmm0,(%r12,%rcx,1)
   9eb23:	add    $0x10,%rcx
   9eb27:	cmp    %rdi,-0xa0(%rbp)
   9eb2e:	ja     9eb0c <__strxfrm_l+0x52dc>
   9eb30:	mov    -0x98(%rbp),%rdi
   9eb37:	add    %rdi,%rax
   9eb3a:	cmp    -0xb0(%rbp),%rdi
   9eb41:	je     9e7ba <__strxfrm_l+0x4f8a>
   9eb47:	lea    (%r14,%rax,1),%rcx
   9eb4b:	movzbl (%rcx,%rdx,1),%ecx
   9eb4f:	mov    %cl,(%r8,%rax,1)
   9eb53:	lea    0x1(%rax),%rcx
   9eb57:	cmp    %rcx,%rsi
   9eb5a:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9eb60:	add    %r14,%rdx
   9eb63:	lea    0x2(%rax),%rcx
   9eb67:	movzbl 0x1(%rax,%rdx,1),%edi
   9eb6c:	cmp    %rcx,%rsi
   9eb6f:	mov    %dil,0x1(%rax,%r8,1)
   9eb74:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9eb7a:	movzbl 0x2(%rax,%rdx,1),%edi
   9eb7f:	lea    0x3(%rax),%rcx
   9eb83:	cmp    %rcx,%rsi
   9eb86:	mov    %dil,0x2(%rax,%r8,1)
   9eb8b:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9eb91:	movzbl 0x3(%rax,%rdx,1),%edi
   9eb96:	lea    0x4(%rax),%rcx
   9eb9a:	cmp    %rcx,%rsi
   9eb9d:	mov    %dil,0x3(%rax,%r8,1)
   9eba2:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9eba8:	movzbl 0x4(%rax,%rdx,1),%edi
   9ebad:	lea    0x5(%rax),%rcx
   9ebb1:	cmp    %rcx,%rsi
   9ebb4:	mov    %dil,0x4(%rax,%r8,1)
   9ebb9:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9ebbf:	movzbl 0x5(%rax,%rdx,1),%edi
   9ebc4:	lea    0x6(%rax),%rcx
   9ebc8:	cmp    %rcx,%rsi
   9ebcb:	mov    %dil,0x5(%rax,%r8,1)
   9ebd0:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9ebd6:	movzbl 0x6(%rax,%rdx,1),%edi
   9ebdb:	lea    0x7(%rax),%rcx
   9ebdf:	cmp    %rcx,%rsi
   9ebe2:	mov    %dil,0x6(%rax,%r8,1)
   9ebe7:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9ebed:	movzbl 0x7(%rax,%rdx,1),%edi
   9ebf2:	lea    0x8(%rax),%rcx
   9ebf6:	cmp    %rcx,%rsi
   9ebf9:	mov    %dil,0x7(%rax,%r8,1)
   9ebfe:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9ec04:	movzbl 0x8(%rax,%rdx,1),%edi
   9ec09:	lea    0x9(%rax),%rcx
   9ec0d:	cmp    %rcx,%rsi
   9ec10:	mov    %dil,0x8(%rax,%r8,1)
   9ec15:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9ec1b:	movzbl 0x9(%rax,%rdx,1),%edi
   9ec20:	lea    0xa(%rax),%rcx
   9ec24:	cmp    %rcx,%rsi
   9ec27:	mov    %dil,0x9(%rax,%r8,1)
   9ec2c:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9ec32:	movzbl 0xa(%rax,%rdx,1),%edi
   9ec37:	lea    0xb(%rax),%rcx
   9ec3b:	cmp    %rcx,%rsi
   9ec3e:	mov    %dil,0xa(%rax,%r8,1)
   9ec43:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9ec49:	movzbl 0xb(%rax,%rdx,1),%edi
   9ec4e:	lea    0xc(%rax),%rcx
   9ec52:	cmp    %rcx,%rsi
   9ec55:	mov    %dil,0xb(%rax,%r8,1)
   9ec5a:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9ec60:	movzbl 0xc(%rax,%rdx,1),%edi
   9ec65:	lea    0xd(%rax),%rcx
   9ec69:	cmp    %rcx,%rsi
   9ec6c:	mov    %dil,0xc(%rax,%r8,1)
   9ec71:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9ec77:	movzbl 0xd(%rax,%rdx,1),%edi
   9ec7c:	add    $0xe,%rax
   9ec80:	mov    %dil,-0x1(%rax,%r8,1)
   9ec85:	cmp    %rax,%rsi
   9ec88:	jbe    9e7ba <__strxfrm_l+0x4f8a>
   9ec8e:	movzbl (%rdx,%rax,1),%edx
   9ec92:	mov    %dl,(%r8,%rax,1)
   9ec96:	jmpq   9e7ba <__strxfrm_l+0x4f8a>
   9ec9b:	cmp    $0xffffffffffffffff,%rdx
   9ec9f:	cmove  -0x48(%rbp),%rdx
   9eca4:	jmpq   9e728 <__strxfrm_l+0x4ef8>
   9eca9:	test   $0xfffff800,%r8d
   9ecb0:	je     9f22d <__strxfrm_l+0x59fd>
   9ecb6:	test   $0xffff0000,%r8d
   9ecbd:	je     9f218 <__strxfrm_l+0x59e8>
   9ecc3:	test   $0xffe00000,%r8d
   9ecca:	je     9f8ff <__strxfrm_l+0x60cf>
   9ecd0:	mov    %r8d,%edx
   9ecd3:	and    $0xfc000000,%edx
   9ecd9:	cmp    $0x1,%edx
   9ecdc:	sbb    %r9,%r9
   9ecdf:	add    $0x6,%r9
   9ece3:	cmp    $0x1,%edx
   9ece6:	sbb    %ecx,%ecx
   9ece8:	add    $0x5,%ecx
   9eceb:	cmp    $0x1,%edx
   9ecee:	sbb    %edx,%edx
   9ecf0:	and    $0xfffffffc,%edx
   9ecf3:	sub    $0x4,%edx
   9ecf6:	mov    %dl,-0x40(%rbp)
   9ecf9:	mov    %r8d,%edx
   9ecfc:	movslq %ecx,%rdi
   9ecff:	and    $0x3f,%edx
   9ed02:	or     $0xffffff80,%edx
   9ed05:	mov    %dl,-0x40(%rbp,%rdi,1)
   9ed09:	mov    %r8d,%edx
   9ed0c:	lea    -0x1(%rcx),%edi
   9ed0f:	sar    $0x6,%edx
   9ed12:	and    $0x3f,%edx
   9ed15:	movslq %edi,%rdi
   9ed18:	or     $0xffffff80,%edx
   9ed1b:	mov    %dl,-0x40(%rbp,%rdi,1)
   9ed1f:	mov    %r8d,%edx
   9ed22:	mov    %ecx,%edi
   9ed24:	sar    $0xc,%edx
   9ed27:	sub    $0x2,%edi
   9ed2a:	je     9ed6d <__strxfrm_l+0x553d>
   9ed2c:	and    $0x3f,%edx
   9ed2f:	movslq %edi,%rdi
   9ed32:	or     $0xffffff80,%edx
   9ed35:	mov    %dl,-0x40(%rbp,%rdi,1)
   9ed39:	mov    %r8d,%edx
   9ed3c:	mov    %ecx,%edi
   9ed3e:	sar    $0x12,%edx
   9ed41:	sub    $0x3,%edi
   9ed44:	je     9ed6d <__strxfrm_l+0x553d>
   9ed46:	and    $0x3f,%edx
   9ed49:	movslq %edi,%rdi
   9ed4c:	or     $0xffffff80,%edx
   9ed4f:	mov    %dl,-0x40(%rbp,%rdi,1)
   9ed53:	mov    %r8d,%edx
   9ed56:	sar    $0x18,%edx
   9ed59:	cmp    $0x4,%ecx
   9ed5c:	je     9ed6d <__strxfrm_l+0x553d>
   9ed5e:	and    $0x3f,%edx
   9ed61:	or     $0xffffff80,%edx
   9ed64:	mov    %dl,-0x3f(%rbp)
   9ed67:	mov    %r8d,%edx
   9ed6a:	sar    $0x1e,%edx
   9ed6d:	lea    0x0(%r13,%r9,1),%rdi
   9ed72:	or     -0x40(%rbp),%dl
   9ed75:	lea    (%rsi,%rdi,1),%rcx
   9ed79:	cmp    %rcx,-0x68(%rbp)
   9ed7d:	mov    %dl,-0x40(%rbp)
   9ed80:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9ed86:	mov    %dl,(%r15,%r13,1)
   9ed8a:	movzbl -0x3f(%rbp),%edx
   9ed8e:	cmp    $0x2,%r9
   9ed92:	mov    %dl,0x1(%r15,%r13,1)
   9ed97:	je     9edd5 <__strxfrm_l+0x55a5>
   9ed99:	movzbl -0x3e(%rbp),%edx
   9ed9d:	cmp    $0x3,%r9
   9eda1:	mov    %dl,0x2(%r15,%r13,1)
   9eda6:	je     9edd5 <__strxfrm_l+0x55a5>
   9eda8:	movzbl -0x3d(%rbp),%edx
   9edac:	cmp    $0x4,%r9
   9edb0:	mov    %dl,0x3(%r15,%r13,1)
   9edb5:	je     9edd5 <__strxfrm_l+0x55a5>
   9edb7:	movzbl -0x3c(%rbp),%edx
   9edbb:	cmp    $0x5,%r9
   9edbf:	mov    %dl,0x4(%r15,%r13,1)
   9edc4:	je     9edd5 <__strxfrm_l+0x55a5>
   9edc6:	movzbl -0x3b(%rbp),%edx
   9edca:	mov    $0x6,%r9d
   9edd0:	mov    %dl,0x5(%r15,%r13,1)
   9edd5:	lea    0x1(%rax),%rcx
   9edd9:	lea    (%r15,%rdi,1),%r8
   9eddd:	lea    0x11(%r14,%rax,1),%rax
   9ede2:	movslq %ebx,%rdx
   9ede5:	lea    (%r14,%rcx,1),%r12
   9ede9:	mov    %rcx,-0xa0(%rbp)
   9edf0:	lea    0x10(%r15,%rdi,1),%rcx
   9edf5:	cmp    %rcx,%r12
   9edf8:	setae  %cl
   9edfb:	cmp    %rax,%r8
   9edfe:	setae  %al
   9ee01:	or     %al,%cl
   9ee03:	je     9f161 <__strxfrm_l+0x5931>
   9ee09:	cmp    $0x14,%r10b
   9ee0d:	jbe    9f161 <__strxfrm_l+0x5931>
   9ee13:	mov    %r12,%rcx
   9ee16:	neg    %rcx
   9ee19:	and    $0xf,%ecx
   9ee1c:	cmp    %rsi,%rcx
   9ee1f:	cmova  %rsi,%rcx
   9ee23:	test   %rcx,%rcx
   9ee26:	je     9f15a <__strxfrm_l+0x592a>
   9ee2c:	movzbl (%r14,%rdx,1),%eax
   9ee31:	cmp    $0x1,%rcx
   9ee35:	mov    %al,(%r8)
   9ee38:	je     9f1fe <__strxfrm_l+0x59ce>
   9ee3e:	movzbl 0x1(%r14,%rdx,1),%eax
   9ee44:	cmp    $0x2,%rcx
   9ee48:	mov    %al,0x1(%r15,%rdi,1)
   9ee4d:	je     9f1f4 <__strxfrm_l+0x59c4>
   9ee53:	movzbl 0x2(%r14,%rdx,1),%eax
   9ee59:	cmp    $0x3,%rcx
   9ee5d:	mov    %al,0x2(%r15,%rdi,1)
   9ee62:	je     9f1ea <__strxfrm_l+0x59ba>
   9ee68:	movzbl 0x3(%r14,%rdx,1),%eax
   9ee6e:	cmp    $0x4,%rcx
   9ee72:	mov    %al,0x3(%r15,%rdi,1)
   9ee77:	je     9f1e0 <__strxfrm_l+0x59b0>
   9ee7d:	movzbl 0x4(%r14,%rdx,1),%eax
   9ee83:	cmp    $0x5,%rcx
   9ee87:	mov    %al,0x4(%r15,%rdi,1)
   9ee8c:	je     9f1c2 <__strxfrm_l+0x5992>
   9ee92:	movzbl 0x5(%r14,%rdx,1),%eax
   9ee98:	cmp    $0x6,%rcx
   9ee9c:	mov    %al,0x5(%r15,%rdi,1)
   9eea1:	je     9f1b8 <__strxfrm_l+0x5988>
   9eea7:	movzbl 0x6(%r14,%rdx,1),%eax
   9eead:	cmp    $0x7,%rcx
   9eeb1:	mov    %al,0x6(%r15,%rdi,1)
   9eeb6:	je     9f1ae <__strxfrm_l+0x597e>
   9eebc:	movzbl 0x7(%r14,%rdx,1),%eax
   9eec2:	cmp    $0x8,%rcx
   9eec6:	mov    %al,0x7(%r15,%rdi,1)
   9eecb:	je     9f1a4 <__strxfrm_l+0x5974>
   9eed1:	movzbl 0x8(%r14,%rdx,1),%eax
   9eed7:	cmp    $0x9,%rcx
   9eedb:	mov    %al,0x8(%r15,%rdi,1)
   9eee0:	je     9f19a <__strxfrm_l+0x596a>
   9eee6:	movzbl 0x9(%r14,%rdx,1),%eax
   9eeec:	cmp    $0xa,%rcx
   9eef0:	mov    %al,0x9(%r15,%rdi,1)
   9eef5:	je     9f190 <__strxfrm_l+0x5960>
   9eefb:	movzbl 0xa(%r14,%rdx,1),%eax
   9ef01:	cmp    $0xb,%rcx
   9ef05:	mov    %al,0xa(%r15,%rdi,1)
   9ef0a:	je     9f186 <__strxfrm_l+0x5956>
   9ef10:	movzbl 0xb(%r14,%rdx,1),%eax
   9ef16:	cmp    $0xc,%rcx
   9ef1a:	mov    %al,0xb(%r15,%rdi,1)
   9ef1f:	je     9f17c <__strxfrm_l+0x594c>
   9ef25:	movzbl 0xc(%r14,%rdx,1),%eax
   9ef2b:	cmp    $0xd,%rcx
   9ef2f:	mov    %al,0xc(%r15,%rdi,1)
   9ef34:	je     9f1d6 <__strxfrm_l+0x59a6>
   9ef3a:	movzbl 0xd(%r14,%rdx,1),%eax
   9ef40:	cmp    $0xf,%rcx
   9ef44:	mov    %al,0xd(%r15,%rdi,1)
   9ef49:	jne    9f1cc <__strxfrm_l+0x599c>
   9ef4f:	movzbl 0xe(%r14,%rdx,1),%eax
   9ef55:	mov    %al,0xe(%r15,%rdi,1)
   9ef5a:	mov    $0xf,%eax
   9ef5f:	cmp    %rcx,%rsi
   9ef62:	je     9e67c <__strxfrm_l+0x4e4c>
   9ef68:	mov    %rsi,%r12
   9ef6b:	sub    %rcx,%r12
   9ef6e:	mov    %r12,-0xd0(%rbp)
   9ef75:	sub    $0x10,%r12
   9ef79:	shr    $0x4,%r12
   9ef7d:	add    $0x1,%r12
   9ef81:	mov    %r12,-0xc8(%rbp)
   9ef88:	shl    $0x4,%r12
   9ef8c:	mov    %r12,-0xc0(%rbp)
   9ef93:	lea    -0x1(%rsi),%r12
   9ef97:	sub    %rcx,%r12
   9ef9a:	cmp    $0xe,%r12
   9ef9e:	jbe    9f006 <__strxfrm_l+0x57d6>
   9efa0:	mov    -0xa0(%rbp),%r12
   9efa7:	mov    %rax,-0xf0(%rbp)
   9efae:	add    %rcx,%r12
   9efb1:	add    %rdi,%rcx
   9efb4:	lea    (%r15,%rcx,1),%rdi
   9efb8:	add    %r14,%r12
   9efbb:	xor    %ecx,%ecx
   9efbd:	mov    %rdi,-0xa0(%rbp)
   9efc4:	mov    -0xa0(%rbp),%rax
   9efcb:	xor    %edi,%edi
   9efcd:	movdqa (%r12,%rcx,1),%xmm0
   9efd3:	add    $0x1,%rdi
   9efd7:	movups %xmm0,(%rax,%rcx,1)
   9efdb:	add    $0x10,%rcx
   9efdf:	cmp    %rdi,-0xc8(%rbp)
   9efe6:	ja     9efcd <__strxfrm_l+0x579d>
   9efe8:	mov    -0xc0(%rbp),%rdi
   9efef:	mov    -0xf0(%rbp),%rax
   9eff6:	add    %rdi,%rax
   9eff9:	cmp    -0xd0(%rbp),%rdi
   9f000:	je     9e67c <__strxfrm_l+0x4e4c>
   9f006:	lea    (%r14,%rax,1),%rcx
   9f00a:	movzbl (%rcx,%rdx,1),%ecx
   9f00e:	mov    %cl,(%r8,%rax,1)
   9f012:	lea    0x1(%rax),%rcx
   9f016:	cmp    %rcx,%rsi
   9f019:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f01f:	add    %r14,%rdx
   9f022:	lea    0x2(%rax),%rcx
   9f026:	movzbl 0x1(%rax,%rdx,1),%edi
   9f02b:	cmp    %rcx,%rsi
   9f02e:	mov    %dil,0x1(%rax,%r8,1)
   9f033:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f039:	movzbl 0x2(%rax,%rdx,1),%edi
   9f03e:	lea    0x3(%rax),%rcx
   9f042:	cmp    %rcx,%rsi
   9f045:	mov    %dil,0x2(%rax,%r8,1)
   9f04a:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f050:	movzbl 0x3(%rax,%rdx,1),%edi
   9f055:	lea    0x4(%rax),%rcx
   9f059:	cmp    %rcx,%rsi
   9f05c:	mov    %dil,0x3(%rax,%r8,1)
   9f061:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f067:	movzbl 0x4(%rax,%rdx,1),%edi
   9f06c:	lea    0x5(%rax),%rcx
   9f070:	cmp    %rcx,%rsi
   9f073:	mov    %dil,0x4(%rax,%r8,1)
   9f078:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f07e:	movzbl 0x5(%rax,%rdx,1),%edi
   9f083:	lea    0x6(%rax),%rcx
   9f087:	cmp    %rcx,%rsi
   9f08a:	mov    %dil,0x5(%rax,%r8,1)
   9f08f:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f095:	movzbl 0x6(%rax,%rdx,1),%edi
   9f09a:	lea    0x7(%rax),%rcx
   9f09e:	cmp    %rcx,%rsi
   9f0a1:	mov    %dil,0x6(%rax,%r8,1)
   9f0a6:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f0ac:	movzbl 0x7(%rax,%rdx,1),%edi
   9f0b1:	lea    0x8(%rax),%rcx
   9f0b5:	cmp    %rcx,%rsi
   9f0b8:	mov    %dil,0x7(%rax,%r8,1)
   9f0bd:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f0c3:	movzbl 0x8(%rax,%rdx,1),%edi
   9f0c8:	lea    0x9(%rax),%rcx
   9f0cc:	cmp    %rcx,%rsi
   9f0cf:	mov    %dil,0x8(%rax,%r8,1)
   9f0d4:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f0da:	movzbl 0x9(%rax,%rdx,1),%edi
   9f0df:	lea    0xa(%rax),%rcx
   9f0e3:	cmp    %rcx,%rsi
   9f0e6:	mov    %dil,0x9(%rax,%r8,1)
   9f0eb:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f0f1:	movzbl 0xa(%rax,%rdx,1),%edi
   9f0f6:	lea    0xb(%rax),%rcx
   9f0fa:	cmp    %rcx,%rsi
   9f0fd:	mov    %dil,0xa(%rax,%r8,1)
   9f102:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f108:	movzbl 0xb(%rax,%rdx,1),%edi
   9f10d:	lea    0xc(%rax),%rcx
   9f111:	cmp    %rcx,%rsi
   9f114:	mov    %dil,0xb(%rax,%r8,1)
   9f119:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f11f:	movzbl 0xc(%rax,%rdx,1),%edi
   9f124:	lea    0xd(%rax),%rcx
   9f128:	cmp    %rcx,%rsi
   9f12b:	mov    %dil,0xc(%rax,%r8,1)
   9f130:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f136:	movzbl 0xd(%rax,%rdx,1),%edi
   9f13b:	add    $0xe,%rax
   9f13f:	mov    %dil,-0x1(%rax,%r8,1)
   9f144:	cmp    %rax,%rsi
   9f147:	jbe    9e67c <__strxfrm_l+0x4e4c>
   9f14d:	movzbl (%rdx,%rax,1),%edx
   9f151:	mov    %dl,(%r8,%rax,1)
   9f155:	jmpq   9e67c <__strxfrm_l+0x4e4c>
   9f15a:	xor    %eax,%eax
   9f15c:	jmpq   9ef68 <__strxfrm_l+0x5738>
   9f161:	xor    %eax,%eax
   9f163:	add    %r14,%rdx
   9f166:	movzbl (%rdx,%rax,1),%ecx
   9f16a:	mov    %cl,(%r8,%rax,1)
   9f16e:	add    $0x1,%rax
   9f172:	cmp    %rax,%rsi
   9f175:	jne    9f166 <__strxfrm_l+0x5936>
   9f177:	jmpq   9e67c <__strxfrm_l+0x4e4c>
   9f17c:	mov    $0xc,%eax
   9f181:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f186:	mov    $0xb,%eax
   9f18b:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f190:	mov    $0xa,%eax
   9f195:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f19a:	mov    $0x9,%eax
   9f19f:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f1a4:	mov    $0x8,%eax
   9f1a9:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f1ae:	mov    $0x7,%eax
   9f1b3:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f1b8:	mov    $0x6,%eax
   9f1bd:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f1c2:	mov    $0x5,%eax
   9f1c7:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f1cc:	mov    $0xe,%eax
   9f1d1:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f1d6:	mov    $0xd,%eax
   9f1db:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f1e0:	mov    $0x4,%eax
   9f1e5:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f1ea:	mov    $0x3,%eax
   9f1ef:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f1f4:	mov    $0x2,%eax
   9f1f9:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f1fe:	mov    $0x1,%eax
   9f203:	jmpq   9ef5f <__strxfrm_l+0x572f>
   9f208:	add    $0x1,%r8d
   9f20c:	mov    $0xffffffffffffffff,%rdx
   9f213:	jmpq   9e728 <__strxfrm_l+0x4ef8>
   9f218:	mov    $0x3,%r9d
   9f21e:	mov    $0x2,%ecx
   9f223:	mov    $0xffffffe0,%edx
   9f228:	jmpq   9ecf6 <__strxfrm_l+0x54c6>
   9f22d:	mov    %r8d,%edx
   9f230:	movb   $0xc0,-0x40(%rbp)
   9f234:	mov    $0x2,%r9d
   9f23a:	and    $0x3f,%edx
   9f23d:	or     $0xffffff80,%edx
   9f240:	mov    %dl,-0x3f(%rbp)
   9f243:	mov    %r8d,%edx
   9f246:	sar    $0x6,%edx
   9f249:	jmpq   9ed6d <__strxfrm_l+0x553d>
   9f24e:	mov    $0x4,%r9d
   9f254:	mov    $0x3,%ecx
   9f259:	mov    $0xfffffff0,%edx
   9f25e:	jmpq   9e846 <__strxfrm_l+0x5016>
   9f263:	mov    $0x3,%r9d
   9f269:	mov    $0x2,%ecx
   9f26e:	mov    $0xffffffe0,%edx
   9f273:	jmpq   9e846 <__strxfrm_l+0x5016>
   9f278:	mov    %r8d,%edx
   9f27b:	movb   $0xc0,-0x40(%rbp)
   9f27f:	mov    $0x2,%r9d
   9f285:	and    $0x3f,%edx
   9f288:	or     $0xffffff80,%edx
   9f28b:	mov    %dl,-0x3f(%rbp)
   9f28e:	mov    %r8d,%edx
   9f291:	sar    $0x6,%edx
   9f294:	jmpq   9e8bd <__strxfrm_l+0x508d>
   9f299:	mov    %r8b,0x0(%r13,%r15,1)
   9f29e:	mov    $0x1,%r9d
   9f2a4:	jmpq   9e925 <__strxfrm_l+0x50f5>
   9f2a9:	mov    %r8b,(%r15,%r13,1)
   9f2ad:	mov    $0x1,%r9d
   9f2b3:	lea    0x1(%rcx),%r11
   9f2b7:	lea    0x10(%r15,%rdi,1),%r12
   9f2bc:	lea    0x11(%r14,%rcx,1),%rcx
   9f2c1:	lea    (%r15,%rdi,1),%r8
   9f2c5:	movslq %ebx,%rdx
   9f2c8:	lea    (%r14,%r11,1),%rax
   9f2cc:	cmp    %r12,%rax
   9f2cf:	setae  %r12b
   9f2d3:	cmp    %rcx,%r8
   9f2d6:	setae  %cl
   9f2d9:	or     %cl,%r12b
   9f2dc:	je     9f6a4 <__strxfrm_l+0x5e74>
   9f2e2:	cmp    $0x14,%r10b
   9f2e6:	jbe    9f6a4 <__strxfrm_l+0x5e74>
   9f2ec:	neg    %rax
   9f2ef:	mov    %rax,%rcx
   9f2f2:	and    $0xf,%ecx
   9f2f5:	cmp    %rsi,%rcx
   9f2f8:	cmova  %rsi,%rcx
   9f2fc:	test   %rcx,%rcx
   9f2ff:	je     9f69d <__strxfrm_l+0x5e6d>
   9f305:	movzbl (%r14,%rdx,1),%eax
   9f30a:	cmp    $0x1,%rcx
   9f30e:	mov    %al,(%r8)
   9f311:	je     9f693 <__strxfrm_l+0x5e63>
   9f317:	movzbl 0x1(%r14,%rdx,1),%eax
   9f31d:	cmp    $0x2,%rcx
   9f321:	mov    %al,0x1(%r15,%rdi,1)
   9f326:	je     9f689 <__strxfrm_l+0x5e59>
   9f32c:	movzbl 0x2(%r14,%rdx,1),%eax
   9f332:	cmp    $0x3,%rcx
   9f336:	mov    %al,0x2(%r15,%rdi,1)
   9f33b:	je     9f67f <__strxfrm_l+0x5e4f>
   9f341:	movzbl 0x3(%r14,%rdx,1),%eax
   9f347:	cmp    $0x4,%rcx
   9f34b:	mov    %al,0x3(%r15,%rdi,1)
   9f350:	je     9f675 <__strxfrm_l+0x5e45>
   9f356:	movzbl 0x4(%r14,%rdx,1),%eax
   9f35c:	cmp    $0x5,%rcx
   9f360:	mov    %al,0x4(%r15,%rdi,1)
   9f365:	je     9f66b <__strxfrm_l+0x5e3b>
   9f36b:	movzbl 0x5(%r14,%rdx,1),%eax
   9f371:	cmp    $0x6,%rcx
   9f375:	mov    %al,0x5(%r15,%rdi,1)
   9f37a:	je     9f661 <__strxfrm_l+0x5e31>
   9f380:	movzbl 0x6(%r14,%rdx,1),%eax
   9f386:	cmp    $0x7,%rcx
   9f38a:	mov    %al,0x6(%r15,%rdi,1)
   9f38f:	je     9f657 <__strxfrm_l+0x5e27>
   9f395:	movzbl 0x7(%r14,%rdx,1),%eax
   9f39b:	cmp    $0x8,%rcx
   9f39f:	mov    %al,0x7(%r15,%rdi,1)
   9f3a4:	je     9f64d <__strxfrm_l+0x5e1d>
   9f3aa:	movzbl 0x8(%r14,%rdx,1),%eax
   9f3b0:	cmp    $0x9,%rcx
   9f3b4:	mov    %al,0x8(%r15,%rdi,1)
   9f3b9:	je     9f643 <__strxfrm_l+0x5e13>
   9f3bf:	movzbl 0x9(%r14,%rdx,1),%eax
   9f3c5:	cmp    $0xa,%rcx
   9f3c9:	mov    %al,0x9(%r15,%rdi,1)
   9f3ce:	je     9f639 <__strxfrm_l+0x5e09>
   9f3d4:	movzbl 0xa(%r14,%rdx,1),%eax
   9f3da:	cmp    $0xb,%rcx
   9f3de:	mov    %al,0xa(%r15,%rdi,1)
   9f3e3:	je     9f62f <__strxfrm_l+0x5dff>
   9f3e9:	movzbl 0xb(%r14,%rdx,1),%eax
   9f3ef:	cmp    $0xc,%rcx
   9f3f3:	mov    %al,0xb(%r15,%rdi,1)
   9f3f8:	je     9f625 <__strxfrm_l+0x5df5>
   9f3fe:	movzbl 0xc(%r14,%rdx,1),%eax
   9f404:	cmp    $0xd,%rcx
   9f408:	mov    %al,0xc(%r15,%rdi,1)
   9f40d:	je     9f61b <__strxfrm_l+0x5deb>
   9f413:	movzbl 0xd(%r14,%rdx,1),%eax
   9f419:	cmp    $0xf,%rcx
   9f41d:	mov    %al,0xd(%r15,%rdi,1)
   9f422:	jne    9f611 <__strxfrm_l+0x5de1>
   9f428:	movzbl 0xe(%r14,%rdx,1),%eax
   9f42e:	mov    %al,0xe(%r15,%rdi,1)
   9f433:	mov    $0xf,%eax
   9f438:	cmp    %rcx,%rsi
   9f43b:	je     9e709 <__strxfrm_l+0x4ed9>
   9f441:	mov    %rsi,%r12
   9f444:	sub    %rcx,%r12
   9f447:	mov    %r12,-0xc8(%rbp)
   9f44e:	sub    $0x10,%r12
   9f452:	shr    $0x4,%r12
   9f456:	add    $0x1,%r12
   9f45a:	mov    %r12,-0xc0(%rbp)
   9f461:	shl    $0x4,%r12
   9f465:	mov    %r12,-0xa0(%rbp)
   9f46c:	lea    -0x1(%rsi),%r12
   9f470:	sub    %rcx,%r12
   9f473:	cmp    $0xe,%r12
   9f477:	jbe    9f4bd <__strxfrm_l+0x5c8d>
   9f479:	add    %rcx,%r11
   9f47c:	add    %rdi,%rcx
   9f47f:	xor    %edi,%edi
   9f481:	lea    (%r15,%rcx,1),%r12
   9f485:	add    %r14,%r11
   9f488:	xor    %ecx,%ecx
   9f48a:	movdqa (%r11,%rcx,1),%xmm0
   9f490:	add    $0x1,%rdi
   9f494:	movups %xmm0,(%r12,%rcx,1)
   9f499:	add    $0x10,%rcx
   9f49d:	cmp    %rdi,-0xc0(%rbp)
   9f4a4:	ja     9f48a <__strxfrm_l+0x5c5a>
   9f4a6:	mov    -0xa0(%rbp),%rdi
   9f4ad:	add    %rdi,%rax
   9f4b0:	cmp    -0xc8(%rbp),%rdi
   9f4b7:	je     9e709 <__strxfrm_l+0x4ed9>
   9f4bd:	lea    (%r14,%rax,1),%rcx
   9f4c1:	movzbl (%rcx,%rdx,1),%ecx
   9f4c5:	mov    %cl,(%r8,%rax,1)
   9f4c9:	lea    0x1(%rax),%rcx
   9f4cd:	cmp    %rcx,%rsi
   9f4d0:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f4d6:	add    %r14,%rdx
   9f4d9:	lea    0x2(%rax),%rcx
   9f4dd:	movzbl 0x1(%rax,%rdx,1),%edi
   9f4e2:	cmp    %rcx,%rsi
   9f4e5:	mov    %dil,0x1(%rax,%r8,1)
   9f4ea:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f4f0:	movzbl 0x2(%rax,%rdx,1),%edi
   9f4f5:	lea    0x3(%rax),%rcx
   9f4f9:	cmp    %rcx,%rsi
   9f4fc:	mov    %dil,0x2(%rax,%r8,1)
   9f501:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f507:	movzbl 0x3(%rax,%rdx,1),%edi
   9f50c:	lea    0x4(%rax),%rcx
   9f510:	cmp    %rcx,%rsi
   9f513:	mov    %dil,0x3(%rax,%r8,1)
   9f518:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f51e:	movzbl 0x4(%rax,%rdx,1),%edi
   9f523:	lea    0x5(%rax),%rcx
   9f527:	cmp    %rcx,%rsi
   9f52a:	mov    %dil,0x4(%rax,%r8,1)
   9f52f:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f535:	movzbl 0x5(%rax,%rdx,1),%edi
   9f53a:	lea    0x6(%rax),%rcx
   9f53e:	cmp    %rcx,%rsi
   9f541:	mov    %dil,0x5(%rax,%r8,1)
   9f546:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f54c:	movzbl 0x6(%rax,%rdx,1),%edi
   9f551:	lea    0x7(%rax),%rcx
   9f555:	cmp    %rcx,%rsi
   9f558:	mov    %dil,0x6(%rax,%r8,1)
   9f55d:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f563:	movzbl 0x7(%rax,%rdx,1),%edi
   9f568:	lea    0x8(%rax),%rcx
   9f56c:	cmp    %rcx,%rsi
   9f56f:	mov    %dil,0x7(%rax,%r8,1)
   9f574:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f57a:	movzbl 0x8(%rax,%rdx,1),%edi
   9f57f:	lea    0x9(%rax),%rcx
   9f583:	cmp    %rcx,%rsi
   9f586:	mov    %dil,0x8(%rax,%r8,1)
   9f58b:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f591:	movzbl 0x9(%rax,%rdx,1),%edi
   9f596:	lea    0xa(%rax),%rcx
   9f59a:	cmp    %rcx,%rsi
   9f59d:	mov    %dil,0x9(%rax,%r8,1)
   9f5a2:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f5a8:	movzbl 0xa(%rax,%rdx,1),%edi
   9f5ad:	lea    0xb(%rax),%rcx
   9f5b1:	cmp    %rcx,%rsi
   9f5b4:	mov    %dil,0xa(%rax,%r8,1)
   9f5b9:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f5bf:	movzbl 0xb(%rax,%rdx,1),%edi
   9f5c4:	lea    0xc(%rax),%rcx
   9f5c8:	cmp    %rcx,%rsi
   9f5cb:	mov    %dil,0xb(%rax,%r8,1)
   9f5d0:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f5d6:	movzbl 0xc(%rax,%rdx,1),%edi
   9f5db:	lea    0xd(%rax),%rcx
   9f5df:	cmp    %rcx,%rsi
   9f5e2:	mov    %dil,0xc(%rax,%r8,1)
   9f5e7:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f5ed:	movzbl 0xd(%rax,%rdx,1),%edi
   9f5f2:	add    $0xe,%rax
   9f5f6:	mov    %dil,-0x1(%rax,%r8,1)
   9f5fb:	cmp    %rax,%rsi
   9f5fe:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f604:	movzbl (%rdx,%rax,1),%edx
   9f608:	mov    %dl,(%r8,%rax,1)
   9f60c:	jmpq   9e709 <__strxfrm_l+0x4ed9>
   9f611:	mov    $0xe,%eax
   9f616:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f61b:	mov    $0xd,%eax
   9f620:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f625:	mov    $0xc,%eax
   9f62a:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f62f:	mov    $0xb,%eax
   9f634:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f639:	mov    $0xa,%eax
   9f63e:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f643:	mov    $0x9,%eax
   9f648:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f64d:	mov    $0x8,%eax
   9f652:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f657:	mov    $0x7,%eax
   9f65c:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f661:	mov    $0x6,%eax
   9f666:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f66b:	mov    $0x5,%eax
   9f670:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f675:	mov    $0x4,%eax
   9f67a:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f67f:	mov    $0x3,%eax
   9f684:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f689:	mov    $0x2,%eax
   9f68e:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f693:	mov    $0x1,%eax
   9f698:	jmpq   9f438 <__strxfrm_l+0x5c08>
   9f69d:	xor    %eax,%eax
   9f69f:	jmpq   9f441 <__strxfrm_l+0x5c11>
   9f6a4:	xor    %eax,%eax
   9f6a6:	add    %r14,%rdx
   9f6a9:	movzbl (%rdx,%rax,1),%ecx
   9f6ad:	mov    %cl,(%r8,%rax,1)
   9f6b1:	add    $0x1,%rax
   9f6b5:	cmp    %rax,%rsi
   9f6b8:	jne    9f6a9 <__strxfrm_l+0x5e79>
   9f6ba:	jmpq   9e709 <__strxfrm_l+0x4ed9>
   9f6bf:	test   $0xfffff800,%r8d
   9f6c6:	je     9f829 <__strxfrm_l+0x5ff9>
   9f6cc:	test   $0xffff0000,%r8d
   9f6d3:	je     9f814 <__strxfrm_l+0x5fe4>
   9f6d9:	test   $0xffe00000,%r8d
   9f6e0:	je     9f7ff <__strxfrm_l+0x5fcf>
   9f6e6:	mov    %r8d,%eax
   9f6e9:	and    $0xfc000000,%eax
   9f6ee:	cmp    $0x1,%eax
   9f6f1:	sbb    %r9,%r9
   9f6f4:	add    $0x6,%r9
   9f6f8:	cmp    $0x1,%eax
   9f6fb:	sbb    %edx,%edx
   9f6fd:	add    $0x5,%edx
   9f700:	cmp    $0x1,%eax
   9f703:	sbb    %eax,%eax
   9f705:	and    $0xfffffffc,%eax
   9f708:	sub    $0x4,%eax
   9f70b:	mov    %al,-0x40(%rbp)
   9f70e:	mov    %r8d,%eax
   9f711:	movslq %edx,%rdi
   9f714:	and    $0x3f,%eax
   9f717:	or     $0xffffff80,%eax
   9f71a:	mov    %al,-0x40(%rbp,%rdi,1)
   9f71e:	mov    %r8d,%eax
   9f721:	lea    -0x1(%rdx),%edi
   9f724:	sar    $0x6,%eax
   9f727:	and    $0x3f,%eax
   9f72a:	movslq %edi,%rdi
   9f72d:	or     $0xffffff80,%eax
   9f730:	mov    %al,-0x40(%rbp,%rdi,1)
   9f734:	mov    %r8d,%eax
   9f737:	mov    %edx,%edi
   9f739:	sar    $0xc,%eax
   9f73c:	sub    $0x2,%edi
   9f73f:	je     9f782 <__strxfrm_l+0x5f52>
   9f741:	and    $0x3f,%eax
   9f744:	movslq %edi,%rdi
   9f747:	or     $0xffffff80,%eax
   9f74a:	mov    %al,-0x40(%rbp,%rdi,1)
   9f74e:	mov    %r8d,%eax
   9f751:	mov    %edx,%edi
   9f753:	sar    $0x12,%eax
   9f756:	sub    $0x3,%edi
   9f759:	je     9f782 <__strxfrm_l+0x5f52>
   9f75b:	and    $0x3f,%eax
   9f75e:	movslq %edi,%rdi
   9f761:	or     $0xffffff80,%eax
   9f764:	mov    %al,-0x40(%rbp,%rdi,1)
   9f768:	mov    %r8d,%eax
   9f76b:	sar    $0x18,%eax
   9f76e:	cmp    $0x4,%edx
   9f771:	je     9f782 <__strxfrm_l+0x5f52>
   9f773:	and    $0x3f,%eax
   9f776:	or     $0xffffff80,%eax
   9f779:	mov    %al,-0x3f(%rbp)
   9f77c:	mov    %r8d,%eax
   9f77f:	sar    $0x1e,%eax
   9f782:	lea    0x0(%r13,%r9,1),%rdi
   9f787:	or     -0x40(%rbp),%al
   9f78a:	lea    (%rsi,%rdi,1),%rdx
   9f78e:	cmp    %rdx,-0x68(%rbp)
   9f792:	mov    %al,-0x40(%rbp)
   9f795:	jbe    9e709 <__strxfrm_l+0x4ed9>
   9f79b:	mov    %al,(%r15,%r13,1)
   9f79f:	movzbl -0x3f(%rbp),%eax
   9f7a3:	cmp    $0x2,%r9
   9f7a7:	mov    %al,0x1(%r15,%r13,1)
   9f7ac:	je     9f2b3 <__strxfrm_l+0x5a83>
   9f7b2:	movzbl -0x3e(%rbp),%eax
   9f7b6:	cmp    $0x3,%r9
   9f7ba:	mov    %al,0x2(%r15,%r13,1)
   9f7bf:	je     9f2b3 <__strxfrm_l+0x5a83>
   9f7c5:	movzbl -0x3d(%rbp),%eax
   9f7c9:	cmp    $0x4,%r9
   9f7cd:	mov    %al,0x3(%r15,%r13,1)
   9f7d2:	je     9f2b3 <__strxfrm_l+0x5a83>
   9f7d8:	movzbl -0x3c(%rbp),%eax
   9f7dc:	cmp    $0x5,%r9
   9f7e0:	mov    %al,0x4(%r15,%r13,1)
   9f7e5:	je     9f2b3 <__strxfrm_l+0x5a83>
   9f7eb:	movzbl -0x3b(%rbp),%eax
   9f7ef:	mov    $0x6,%r9d
   9f7f5:	mov    %al,0x5(%r15,%r13,1)
   9f7fa:	jmpq   9f2b3 <__strxfrm_l+0x5a83>
   9f7ff:	mov    $0x4,%r9d
   9f805:	mov    $0x3,%edx
   9f80a:	mov    $0xfffffff0,%eax
   9f80f:	jmpq   9f70b <__strxfrm_l+0x5edb>
   9f814:	mov    $0x3,%r9d
   9f81a:	mov    $0x2,%edx
   9f81f:	mov    $0xffffffe0,%eax
   9f824:	jmpq   9f70b <__strxfrm_l+0x5edb>
   9f829:	mov    %r8d,%eax
   9f82c:	movb   $0xc0,-0x40(%rbp)
   9f830:	mov    $0x2,%r9d
   9f836:	and    $0x3f,%eax
   9f839:	or     $0xffffff80,%eax
   9f83c:	mov    %al,-0x3f(%rbp)
   9f83f:	mov    %r8d,%eax
   9f842:	sar    $0x6,%eax
   9f845:	jmpq   9f782 <__strxfrm_l+0x5f52>
   9f84a:	movzbl -0x60(%rbp),%edi
   9f84e:	mov    -0x58(%rbp),%rax
   9f852:	mov    %dil,(%r12,%rax,1)
   9f856:	mov    $0x1,%edi
   9f85b:	jmpq   9aba2 <__strxfrm_l+0x1372>
   9f860:	xor    %eax,%eax
   9f862:	movzbl (%rdi,%rax,1),%edx
   9f866:	mov    %dl,(%r9,%rax,1)
   9f86a:	add    $0x1,%rax
   9f86e:	cmp    %rax,%r11
   9f871:	jne    9f862 <__strxfrm_l+0x6032>
   9f873:	jmpq   9c70f <__strxfrm_l+0x2edf>
   9f878:	mov    %rdx,-0x58(%rbp)
   9f87c:	jmpq   9c712 <__strxfrm_l+0x2ee2>
   9f881:	mov    %r9d,%ecx
   9f884:	jmpq   9c418 <__strxfrm_l+0x2be8>
   9f889:	xor    %edi,%edi
   9f88b:	jmpq   9d023 <__strxfrm_l+0x37f3>
   9f890:	movzbl -0x60(%rbp),%esi
   9f894:	mov    -0x58(%rbp),%rbx
   9f898:	mov    $0x1,%r11d
   9f89e:	mov    %sil,0x0(%r13,%rbx,1)
   9f8a3:	jmpq   9b4c4 <__strxfrm_l+0x1c94>
   9f8a8:	mov    %edi,%ecx
   9f8aa:	movb   $0xc0,-0x40(%rbp)
   9f8ae:	mov    $0x2,%r9d
   9f8b4:	and    $0x3f,%ecx
   9f8b7:	or     $0xffffff80,%ecx
   9f8ba:	mov    %cl,-0x3f(%rbp)
   9f8bd:	mov    %edi,%ecx
   9f8bf:	sar    $0x6,%ecx
   9f8c2:	jmpq   9a3b0 <__strxfrm_l+0xb80>
   9f8c7:	mov    %r12d,%eax
   9f8ca:	jmpq   9e2f3 <__strxfrm_l+0x4ac3>
   9f8cf:	cmp    %r11,-0x68(%rbp)
   9f8d3:	jb     9f8db <__strxfrm_l+0x60ab>
   9f8d5:	movb   $0x0,-0x1(%r13,%r11,1)
   9f8db:	lea    -0x1(%r11),%r13
   9f8df:	jmpq   99895 <__strxfrm_l+0x65>
   9f8e4:	mov    %rdi,%r13
   9f8e7:	sub    $0x1,%r13
   9f8eb:	jmpq   99895 <__strxfrm_l+0x65>
   9f8f0:	mov    %r8b,(%r15,%r13,1)
   9f8f4:	mov    $0x1,%r9d
   9f8fa:	jmpq   9edd5 <__strxfrm_l+0x55a5>
   9f8ff:	mov    $0x4,%r9d
   9f905:	mov    $0x3,%ecx
   9f90a:	mov    $0xfffffff0,%edx
   9f90f:	jmpq   9ecf6 <__strxfrm_l+0x54c6>
   9f914:	cltq   
   9f916:	xor    %esi,%esi
   9f918:	add    %r14,%rax
   9f91b:	movzbl (%rax,%rsi,1),%edi
   9f91f:	mov    %dil,(%r11,%rsi,1)
   9f923:	add    $0x1,%rsi
   9f927:	cmp    %rsi,%rdx
   9f92a:	jne    9f91b <__strxfrm_l+0x60eb>
   9f92c:	lea    0x2(%rcx),%r12d
   9f930:	jmpq   9e4c0 <__strxfrm_l+0x4c90>
   9f935:	mov    -0x48(%rbp),%eax
   9f938:	jmpq   9e2f3 <__strxfrm_l+0x4ac3>
   9f93d:	mov    %r12d,%eax
   9f940:	jmpq   9de34 <__strxfrm_l+0x4604>
   9f945:	mov    %r8d,%eax
   9f948:	jmpq   9de34 <__strxfrm_l+0x4604>
   9f94d:	mov    %r9,%r10
   9f950:	mov    %r15,%rdi
   9f953:	lea    0x2(%rsi),%r8d
   9f957:	jmpq   9de3d <__strxfrm_l+0x460d>
   9f95c:	cltq   
   9f95e:	xor    %ecx,%ecx
   9f960:	add    %r14,%rax
   9f963:	movzbl (%rax,%rcx,1),%edi
   9f967:	mov    %dil,(%r10,%rcx,1)
   9f96b:	add    $0x1,%rcx
   9f96f:	cmp    %rcx,%rdx
   9f972:	jne    9f963 <__strxfrm_l+0x6133>
   9f974:	lea    0x2(%rsi),%r8d
   9f978:	jmpq   9dfea <__strxfrm_l+0x47ba>
   9f97d:	mov    %r13d,%eax
   9f980:	jmpq   9d9d7 <__strxfrm_l+0x41a7>
   9f985:	mov    -0xa0(%rbp),%eax
   9f98b:	jmpq   9d9d7 <__strxfrm_l+0x41a7>
   9f990:	mov    -0x98(%rbp),%eax
   9f996:	jmpq   9d9d7 <__strxfrm_l+0x41a7>
   9f99b:	mov    $0xe,%eax
   9f9a0:	jmpq   9eaad <__strxfrm_l+0x527d>
   9f9a5:	mov    $0xd,%eax
   9f9aa:	jmpq   9eaad <__strxfrm_l+0x527d>
   9f9af:	mov    $0xc,%eax
   9f9b4:	jmpq   9eaad <__strxfrm_l+0x527d>
   9f9b9:	mov    $0xb,%eax
   9f9be:	jmpq   9eaad <__strxfrm_l+0x527d>
   9f9c3:	mov    $0xa,%eax
   9f9c8:	jmpq   9eaad <__strxfrm_l+0x527d>
   9f9cd:	mov    $0x9,%eax
   9f9d2:	jmpq   9eaad <__strxfrm_l+0x527d>
   9f9d7:	mov    $0x8,%eax
   9f9dc:	jmpq   9eaad <__strxfrm_l+0x527d>
   9f9e1:	mov    $0x7,%eax
   9f9e6:	jmpq   9eaad <__strxfrm_l+0x527d>
   9f9eb:	mov    $0x6,%eax
   9f9f0:	jmpq   9eaad <__strxfrm_l+0x527d>
   9f9f5:	mov    $0x5,%eax
   9f9fa:	jmpq   9eaad <__strxfrm_l+0x527d>
   9f9ff:	mov    $0x4,%eax
   9fa04:	jmpq   9eaad <__strxfrm_l+0x527d>
   9fa09:	mov    $0x3,%eax
   9fa0e:	jmpq   9eaad <__strxfrm_l+0x527d>
   9fa13:	mov    $0x2,%eax
   9fa18:	jmpq   9eaad <__strxfrm_l+0x527d>
   9fa1d:	mov    $0x1,%eax
   9fa22:	jmpq   9eaad <__strxfrm_l+0x527d>
   9fa27:	xor    %eax,%eax
   9fa29:	jmpq   9eab6 <__strxfrm_l+0x5286>
   9fa2e:	xor    %eax,%eax
   9fa30:	add    %r14,%rdx
   9fa33:	movzbl (%rdx,%rax,1),%ecx
   9fa37:	mov    %cl,(%r8,%rax,1)
   9fa3b:	add    $0x1,%rax
   9fa3f:	cmp    %rax,%rsi
   9fa42:	jne    9fa33 <__strxfrm_l+0x6203>
   9fa44:	jmpq   9e7ba <__strxfrm_l+0x4f8a>
   9fa49:	nopl   0x0(%rax)
