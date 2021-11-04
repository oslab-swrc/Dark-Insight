// TC_OUT pthread_spin_lock,0x10,0x17,0x0(%rdi)
0000000000000000 <pthread_spin_lock>:
   0:	lock decl (%rdi)
   3:	jne    10 <pthread_spin_lock+0x10>
   5:	xor    %eax,%eax
   7:	retq
   8:	nopl   0x0(%rax,%rax,1)
  10:	pause
  12:	cmpl   $0x0,(%rdi)
  15:	jg     0 <pthread_spin_lock>
  17:	jmp    10 <pthread_spin_lock+0x10>
