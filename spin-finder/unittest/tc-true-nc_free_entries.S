// TC_OUT _nc_free_entries@@Base,0x101c0,0x101cb,0x0(%rbx)
00000000000101b0 <_nc_free_entries@@Base>:
   101b0:	push   %rbx
   101b1:	mov    0x21a988(%rip),%rbx        # 22ab40 <boolnames@@Base+0x460>
   101b8:	mov    (%rbx),%rdi
   101bb:	test   %rdi,%rdi
   101be:	je     101cd <_nc_free_entries@@Base+0x1d>
   101c0:	callq  d700 <_init@@Base+0x268>
   101c5:	mov    (%rbx),%rdi
   101c8:	test   %rdi,%rdi
   101cb:	jne    101c0 <_nc_free_entries@@Base+0x10>
   101cd:	pop    %rbx
   101ce:	retq
   101cf:	nop

