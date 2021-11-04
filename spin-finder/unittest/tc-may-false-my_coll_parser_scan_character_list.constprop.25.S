# loop exit condition is updated inside loop, but through calling function
# to get the next pointer (p = p->next)
00000000012f86e0 <my_coll_parser_scan_character_list.constprop.25>:
 12f86e0:	push   %rbp
 12f86e1:	mov    %rsp,%rbp
 12f86e4:	push   %r14
 12f86e6:	push   %r13
 12f86e8:	push   %r12
 12f86ea:	push   %rbx
 12f86eb:	cmpl   $0x5,(%rdi)
 12f86ee:	mov    %rdi,%rbx
 12f86f1:	jne    12f8780 <my_coll_parser_scan_character_list.constprop.25+0xa0>
 12f86f7:	cmpq   $0x0,(%rsi)
 12f86fb:	mov    %rdx,%r13
 12f86fe:	mov    %rsi,%r12
 12f8701:	movslq 0x24(%rdi),%rdx
 12f8705:	je     12f8770 <my_coll_parser_scan_character_list.constprop.25+0x90>
 12f8707:	cmpq   $0x0,0x8(%rsi)
 12f870c:	lea    0x8(%rsi),%rax
 12f8710:	je     12f8778 <my_coll_parser_scan_character_list.constprop.25+0x98>
 12f8712:	cmpq   $0x0,0x10(%rsi)
 12f8717:	lea    0x10(%rsi),%rax
 12f871b:	je     12f8778 <my_coll_parser_scan_character_list.constprop.25+0x98>
 12f871d:	cmpq   $0x0,0x18(%rsi)
 12f8722:	lea    0x18(%rsi),%rax
 12f8726:	je     12f8778 <my_coll_parser_scan_character_list.constprop.25+0x98>
 12f8728:	cmpq   $0x0,0x20(%rsi)
 12f872d:	lea    0x20(%rsi),%rax
 12f8731:	je     12f8778 <my_coll_parser_scan_character_list.constprop.25+0x98>
 12f8733:	cmpq   $0x0,0x28(%rsi)
 12f8738:	lea    0x28(%rsi),%rax
 12f873c:	je     12f8778 <my_coll_parser_scan_character_list.constprop.25+0x98>
 12f873e:	xchg   %ax,%ax
 12f8740:	lea    0xd8(%rbx),%rdi
 12f8747:	lea    0x548168(%rip),%rdx        # 18408b6 <t_ctype+0x1416>
 12f874e:	mov    %r13,%rcx
 12f8751:	mov    $0x80,%esi
 12f8756:	xor    %eax,%eax
 12f8758:	callq  1313550 <my_snprintf>
 12f875d:	pop    %rbx
 12f875e:	pop    %r12
 12f8760:	pop    %r13
 12f8762:	pop    %r14
 12f8764:	xor    %eax,%eax
 12f8766:	pop    %rbp
 12f8767:	retq   
 12f8768:	nopl   0x0(%rax,%rax,1)
 12f8770:	mov    %rsi,%rax
 12f8773:	nopl   0x0(%rax,%rax,1)
 12f8778:	mov    %rdx,(%rax)
 12f877b:	cmpl   $0x5,(%rbx)
 12f877e:	je     12f87b0 <my_coll_parser_scan_character_list.constprop.25+0xd0>
 12f8780:	lea    0xd8(%rbx),%rdi
 12f8787:	lea    0x548112(%rip),%rcx        # 18408a0 <t_ctype+0x1400>
 12f878e:	lea    0x548115(%rip),%rdx        # 18408aa <t_ctype+0x140a>
 12f8795:	mov    $0x80,%esi
 12f879a:	xor    %eax,%eax
 12f879c:	callq  1313550 <my_snprintf>
 12f87a1:	xor    %eax,%eax
 12f87a3:	pop    %rbx
 12f87a4:	pop    %r12
 12f87a6:	pop    %r13
 12f87a8:	pop    %r14
 12f87aa:	pop    %rbp
 12f87ab:	retq   
 12f87ac:	nopl   0x0(%rax)
 12f87b0:	mov    0x28(%rbx),%rax
 12f87b4:	lea    0x28(%rbx),%r14
 12f87b8:	mov    %r14,%rdi
 12f87bb:	mov    %rax,(%rbx)
 12f87be:	mov    0x30(%rbx),%rax
 12f87c2:	mov    %rax,0x8(%rbx)
 12f87c6:	mov    0x38(%rbx),%rax
 12f87ca:	mov    %rax,0x10(%rbx)
 12f87ce:	mov    0x40(%rbx),%rax
 12f87d2:	mov    %rax,0x18(%rbx)
 12f87d6:	mov    0x48(%rbx),%rax
 12f87da:	mov    %rax,0x20(%rbx)
 12f87de:	callq  12f7c10 <my_coll_lexem_next>
 12f87e3:	cmpl   $0x5,(%rbx)
 12f87e6:	jne    12f8883 <my_coll_parser_scan_character_list.constprop.25+0x1a3>
 12f87ec:	nopl   0x0(%rax)
 12f87f0:	cmpq   $0x0,(%r12)
 12f87f5:	movslq 0x24(%rbx),%rax
 12f87f9:	je     12f8890 <my_coll_parser_scan_character_list.constprop.25+0x1b0>
 12f87ff:	cmpq   $0x0,0x8(%r12)
 12f8805:	lea    0x8(%r12),%rdx
 12f880a:	je     12f8848 <my_coll_parser_scan_character_list.constprop.25+0x168>
 12f880c:	cmpq   $0x0,0x10(%r12)
 12f8812:	lea    0x10(%r12),%rdx
 12f8817:	je     12f8848 <my_coll_parser_scan_character_list.constprop.25+0x168>
 12f8819:	cmpq   $0x0,0x18(%r12)
 12f881f:	lea    0x18(%r12),%rdx
 12f8824:	je     12f8848 <my_coll_parser_scan_character_list.constprop.25+0x168>
 12f8826:	cmpq   $0x0,0x20(%r12)
 12f882c:	lea    0x20(%r12),%rdx
 12f8831:	je     12f8848 <my_coll_parser_scan_character_list.constprop.25+0x168>
 12f8833:	cmpq   $0x0,0x28(%r12)
 12f8839:	jne    12f8740 <my_coll_parser_scan_character_list.constprop.25+0x60>
 12f883f:	lea    0x28(%r12),%rdx
 12f8844:	nopl   0x0(%rax)
 12f8848:	mov    %rax,(%rdx)
 12f884b:	mov    0x28(%rbx),%rax
 12f884f:	mov    %r14,%rdi
 12f8852:	mov    %rax,(%rbx)
 12f8855:	mov    0x30(%rbx),%rax
 12f8859:	mov    %rax,0x8(%rbx)
 12f885d:	mov    0x38(%rbx),%rax
 12f8861:	mov    %rax,0x10(%rbx)
 12f8865:	mov    0x40(%rbx),%rax
 12f8869:	mov    %rax,0x18(%rbx)
 12f886d:	mov    0x48(%rbx),%rax
 12f8871:	mov    %rax,0x20(%rbx)
 12f8875:	callq  12f7c10 <my_coll_lexem_next>
 12f887a:	cmpl   $0x5,(%rbx)
 12f887d:	je     12f87f0 <my_coll_parser_scan_character_list.constprop.25+0x110>
 12f8883:	mov    $0x1,%eax
 12f8888:	jmpq   12f87a3 <my_coll_parser_scan_character_list.constprop.25+0xc3>
 12f888d:	nopl   (%rax)
 12f8890:	mov    %r12,%rdx
 12f8893:	jmp    12f8848 <my_coll_parser_scan_character_list.constprop.25+0x168>
 12f8895:	data32 nopw %cs:0x0(%rax,%rax,1)
