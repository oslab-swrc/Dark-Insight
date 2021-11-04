// TC_OUT
0000000000ebda50 <tree_search_next>:
  ebda50:	mov    (%rsi),%rax
  ebda53:	push   %rbp
  ebda54:	movslq %ecx,%rcx
  ebda57:	lea    0x8(%rdi),%r9
  ebda5b:	mov    %rsp,%rbp
  ebda5e:	mov    (%rax),%r10
  ebda61:	mov    (%r10,%rcx,1),%r8
  ebda65:	cmp    %r9,%r8
  ebda68:	je     ebdac0 <tree_search_next+0x70>
  ebda6a:	lea    0x8(%rax),%rcx
  ebda6e:	movslq %edx,%rdx
  ebda71:	mov    %rcx,(%rsi)
  ebda74:	mov    %r8,0x8(%rax)
  ebda78:	mov    (%r8,%rdx,1),%rax
  ebda7c:	cmp    %rax,%r9
  ebda7f:	jne    ebda8b <tree_search_next+0x3b>
  ebda81:	jmp    ebdafc <tree_search_next+0xac>
  ebda83:	nopl   0x0(%rax,%rax,1)
  ebda88:	mov    %rcx,%rax
  ebda8b:	mov    (%rsi),%rcx
  ebda8e:	lea    0x8(%rcx),%r8
  ebda92:	mov    %r8,(%rsi)
  ebda95:	mov    %rax,0x8(%rcx)
  ebda99:	mov    (%rax,%rdx,1),%rcx
  ebda9d:	cmp    %rcx,%r9
  ebdaa0:	jne    ebda88 <tree_search_next+0x38>
  ebdaa2:	mov    0x220(%rdi),%edx
  ebdaa8:	test   %edx,%edx
  ebdaaa:	je     ebdab8 <tree_search_next+0x68>
  ebdaac:	add    %rdx,%rax
  ebdaaf:	pop    %rbp
  ebdab0:	retq   
  ebdab1:	nopl   0x0(%rax)
  ebdab8:	mov    0x18(%rax),%rax
  ebdabc:	pop    %rbp
  ebdabd:	retq   
  ebdabe:	xchg   %ax,%ax
  ebdac0:	lea    -0x8(%rax),%rdx
  ebdac4:	mov    %rdx,(%rsi)
  ebdac7:	mov    -0x8(%rax),%r9
  ebdacb:	cmp    %r9,%r8
  ebdace:	je     ebdaf8 <tree_search_next+0xa8>
  ebdad0:	cmp    (%r9,%rcx,1),%r10
  ebdad4:	jne    ebdb01 <tree_search_next+0xb1>
  ebdad6:	sub    $0x10,%rax
  ebdada:	jmp    ebdaed <tree_search_next+0x9d>
  ebdadc:	nopl   0x0(%rax)
  ebdae0:	sub    $0x8,%rax
  ebdae4:	cmp    %r9,(%rdx,%rcx,1)
  ebdae8:	jne    ebdb04 <tree_search_next+0xb4>
  ebdaea:	mov    %rdx,%r9
  ebdaed:	mov    %rax,(%rsi)
  ebdaf0:	mov    (%rax),%rdx
  ebdaf3:	cmp    %rdx,%r8
  ebdaf6:	jne    ebdae0 <tree_search_next+0x90>
  ebdaf8:	xor    %eax,%eax
  ebdafa:	pop    %rbp
  ebdafb:	retq   
  ebdafc:	mov    %r8,%rax
  ebdaff:	jmp    ebdaa2 <tree_search_next+0x52>
  ebdb01:	mov    %r9,%rdx
  ebdb04:	mov    0x220(%rdi),%ecx
  ebdb0a:	mov    %ecx,%eax
  ebdb0c:	add    %rdx,%rax
  ebdb0f:	test   %ecx,%ecx
  ebdb11:	jne    ebdaaf <tree_search_next+0x5f>
  ebdb13:	mov    0x18(%rdx),%rax
  ebdb17:	pop    %rbp
  ebdb18:	retq   
  ebdb19:	nopl   0x0(%rax)
