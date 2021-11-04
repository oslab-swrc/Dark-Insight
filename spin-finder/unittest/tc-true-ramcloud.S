// TC_OUT RAMCloud::SpinLock::lock,0x495e86,0x4960c7,0x0(0x8<-0x88(%rbp)>)
0000000000495e5c <RAMCloud::SpinLock::lock()>:
  495e5c:	push   %rbp
  495e5d:	mov    %rsp,%rbp
  495e60:	push   %rbx
  495e61:	sub    $0x88,%rsp
  495e68:	mov    %rdi,-0x88(%rbp)
  495e6f:	mov    %fs:0x28,%rax
  495e78:	mov    %rax,-0x18(%rbp)
  495e7c:	xor    %eax,%eax
  495e7e:	movq   $0x0,-0x60(%rbp)
  495e86:	mov    -0x88(%rbp),%rax
  495e8d:	add    $0x8,%rax
  495e91:	mov    %rax,-0x48(%rbp)
  495e95:	movl   $0x2,-0x7c(%rbp)
  495e9c:	mov    -0x48(%rbp),%rdx
  495ea0:	mov    $0x1,%eax
  495ea5:	xchg   %al,(%rdx)
  495ea7:	test   %al,%al
  495ea9:	je     4960cc <RAMCloud::SpinLock::lock()+0x270>
  495eaf:	cmpq   $0x0,-0x60(%rbp)
  495eb4:	jne    495f44 <RAMCloud::SpinLock::lock()+0xe8>
  495eba:	lea    0x3d266f(%rip),%rax        # 868530 <RAMCloud::Cycles::mockTscValue>
  495ec1:	mov    (%rax),%rax
  495ec4:	test   %rax,%rax
  495ec7:	je     495ed5 <RAMCloud::SpinLock::lock()+0x79>
  495ec9:	lea    0x3d2660(%rip),%rax        # 868530 <RAMCloud::Cycles::mockTscValue>
  495ed0:	mov    (%rax),%rax
  495ed3:	jmp    495eee <RAMCloud::SpinLock::lock()+0x92>
  495ed5:	rdtscp 
  495ed8:	mov    %eax,-0x78(%rbp)
  495edb:	mov    %edx,-0x74(%rbp)
  495ede:	mov    -0x74(%rbp),%eax
  495ee1:	shl    $0x20,%rax
  495ee5:	mov    %rax,%rdx
  495ee8:	mov    -0x78(%rbp),%eax
  495eeb:	or     %rdx,%rax
  495eee:	mov    %rax,-0x60(%rbp)
  495ef2:	mov    -0x88(%rbp),%rax
  495ef9:	movzbl 0x48(%rax),%eax
  495efd:	test   %al,%al
  495eff:	je     495e86 <RAMCloud::SpinLock::lock()+0x2a>
  495f01:	lea    -0x40(%rbp),%rax
  495f05:	lea    0xe94b4(%rip),%r8        # 57f3c0 <RAMCloud::SpinLock::lock()::__PRETTY_FUNCTION__>
  495f0c:	lea    0xe94a5(%rip),%rcx        # 57f3b8 <RAMCloud::SpinLock::lock()::__func__>
  495f13:	mov    $0x56,%edx
  495f18:	lea    0xe93b1(%rip),%rsi        # 57f2d0 <google::protobuf::internal::kMinRepeatedFieldAllocationSize+0x4>
  495f1f:	mov    %rax,%rdi
  495f22:	callq  30d422 <RAMCloud::CodeLocation::CodeLocation(char const*, unsigned int, char const*, char const*)>
  495f27:	lea    -0x40(%rbp),%rax
  495f2b:	lea    0xe93cf(%rip),%rsi        # 57f301 <google::protobuf::internal::kMinRepeatedFieldAllocationSize+0x35>
  495f32:	mov    %rax,%rdi
  495f35:	mov    $0x0,%eax
  495f3a:	callq  4abf69 <RAMCloud::TestLog::log(RAMCloud::CodeLocation const&, char const*, ...)>
  495f3f:	jmpq   495e86 <RAMCloud::SpinLock::lock()+0x2a>
  495f44:	lea    0x3d25e5(%rip),%rax        # 868530 <RAMCloud::Cycles::mockTscValue>
  495f4b:	mov    (%rax),%rax
  495f4e:	test   %rax,%rax
  495f51:	je     495f5f <RAMCloud::SpinLock::lock()+0x103>
  495f53:	lea    0x3d25d6(%rip),%rax        # 868530 <RAMCloud::Cycles::mockTscValue>
  495f5a:	mov    (%rax),%rax
  495f5d:	jmp    495f78 <RAMCloud::SpinLock::lock()+0x11c>
  495f5f:	rdtscp 
  495f62:	mov    %eax,-0x70(%rbp)
  495f65:	mov    %edx,-0x6c(%rbp)
  495f68:	mov    -0x6c(%rbp),%eax
  495f6b:	shl    $0x20,%rax
  495f6f:	mov    %rax,%rdx
  495f72:	mov    -0x70(%rbp),%eax
  495f75:	or     %rdx,%rax
  495f78:	mov    %rax,-0x58(%rbp)
  495f7c:	mov    -0x58(%rbp),%rax
  495f80:	sub    -0x60(%rbp),%rax
  495f84:	vxorpd %xmm0,%xmm0,%xmm0
  495f88:	mov    %rax,%rdi
  495f8b:	callq  3966b6 <RAMCloud::Cycles::toSeconds(unsigned long, double)>
  495f90:	vmovq  %xmm0,%rax
  495f95:	vmovsd 0xe9503(%rip),%xmm0        # 57f4a0 <int RAMCloud::downCast<int, unsigned long>(unsigned long const&)::__PRETTY_FUNCTION__+0x60>
  495f9d:	vmovq  %rax,%xmm1
  495fa2:	vucomisd %xmm0,%xmm1
  495fa6:	seta   %al
  495fa9:	test   %al,%al
  495fab:	je     495e86 <RAMCloud::SpinLock::lock()+0x2a>
  495fb1:	callq  3de9c6 <RAMCloud::Logger::get()>
  495fb6:	mov    %rax,-0x50(%rbp)
  495fba:	mov    -0x50(%rbp),%rax
  495fbe:	mov    $0x2,%edx
  495fc3:	mov    $0x0,%esi
  495fc8:	mov    %rax,%rdi
  495fcb:	callq  30d602 <RAMCloud::Logger::isLogging(RAMCloud::LogModule, RAMCloud::LogLevel)>
  495fd0:	test   %al,%al
  495fd2:	je     496047 <RAMCloud::SpinLock::lock()+0x1eb>
  495fd4:	mov    -0x88(%rbp),%rax
  495fdb:	add    $0x10,%rax
  495fdf:	mov    %rax,%rdi
  495fe2:	callq  307f40 <.plt.got+0xc0>
  495fe7:	mov    %rax,%rbx
  495fea:	lea    -0x40(%rbp),%rax
  495fee:	lea    0xe93cb(%rip),%r8        # 57f3c0 <RAMCloud::SpinLock::lock()::__PRETTY_FUNCTION__>
  495ff5:	lea    0xe93bc(%rip),%rcx        # 57f3b8 <RAMCloud::SpinLock::lock()::__func__>
  495ffc:	mov    $0x5d,%edx
  496001:	lea    0xe92c8(%rip),%rsi        # 57f2d0 <google::protobuf::internal::kMinRepeatedFieldAllocationSize+0x4>
  496008:	mov    %rax,%rdi
  49600b:	callq  30d422 <RAMCloud::CodeLocation::CodeLocation(char const*, unsigned int, char const*, char const*)>
  496010:	lea    -0x40(%rbp),%rdx
  496014:	mov    -0x50(%rbp),%rax
  496018:	sub    $0x8,%rsp
  49601c:	push   %rbx
  49601d:	lea    0xe92f4(%rip),%r9        # 57f318 <google::protobuf::internal::kMinRepeatedFieldAllocationSize+0x4c>
  496024:	mov    %rdx,%r8
  496027:	mov    $0x2,%ecx
  49602c:	mov    $0x0,%edx
  496031:	mov    $0x0,%esi
  496036:	mov    %rax,%rdi
  496039:	mov    $0x0,%eax
  49603e:	callq  3df5f4 <RAMCloud::Logger::logMessage(bool, RAMCloud::LogModule, RAMCloud::LogLevel, RAMCloud::CodeLocation const&, char const*, ...)>
  496043:	add    $0x10,%rsp
  496047:	mov    -0x88(%rbp),%rax
  49604e:	add    $0x10,%rax
  496052:	mov    %rax,%rdi
  496055:	callq  307f40 <.plt.got+0xc0>
  49605a:	mov    %rax,%rbx
  49605d:	lea    -0x40(%rbp),%rax
  496061:	lea    0xe9358(%rip),%r8        # 57f3c0 <RAMCloud::SpinLock::lock()::__PRETTY_FUNCTION__>
  496068:	lea    0xe9349(%rip),%rcx        # 57f3b8 <RAMCloud::SpinLock::lock()::__func__>
  49606f:	mov    $0x5d,%edx
  496074:	lea    0xe9255(%rip),%rsi        # 57f2d0 <google::protobuf::internal::kMinRepeatedFieldAllocationSize+0x4>
  49607b:	mov    %rax,%rdi
  49607e:	callq  30d422 <RAMCloud::CodeLocation::CodeLocation(char const*, unsigned int, char const*, char const*)>
  496083:	lea    -0x40(%rbp),%rax
  496087:	mov    %rbx,%rdx
  49608a:	lea    0xe92b7(%rip),%rsi        # 57f348 <google::protobuf::internal::kMinRepeatedFieldAllocationSize+0x7c>
  496091:	mov    %rax,%rdi
  496094:	mov    $0x0,%eax
  496099:	callq  4abf69 <RAMCloud::TestLog::log(RAMCloud::CodeLocation const&, char const*, ...)>
  49609e:	mov    -0x88(%rbp),%rax
  4960a5:	mov    0x40(%rax),%rdx
  4960a9:	mov    -0x58(%rbp),%rax
  4960ad:	sub    -0x60(%rbp),%rax
  4960b1:	add    %rax,%rdx
  4960b4:	mov    -0x88(%rbp),%rax
  4960bb:	mov    %rdx,0x40(%rax)
  4960bf:	mov    -0x58(%rbp),%rax
  4960c3:	mov    %rax,-0x60(%rbp)
  4960c7:	jmpq   495e86 <RAMCloud::SpinLock::lock()+0x2a>
  4960cc:	cmpq   $0x0,-0x60(%rbp)
  4960d1:	je     496141 <RAMCloud::SpinLock::lock()+0x2e5>
  4960d3:	lea    0x3d2456(%rip),%rax        # 868530 <RAMCloud::Cycles::mockTscValue>
  4960da:	mov    (%rax),%rax
  4960dd:	test   %rax,%rax
  4960e0:	je     4960ee <RAMCloud::SpinLock::lock()+0x292>
  4960e2:	lea    0x3d2447(%rip),%rax        # 868530 <RAMCloud::Cycles::mockTscValue>
  4960e9:	mov    (%rax),%rax
  4960ec:	jmp    496107 <RAMCloud::SpinLock::lock()+0x2ab>
  4960ee:	rdtscp 
  4960f1:	mov    %eax,-0x68(%rbp)
  4960f4:	mov    %edx,-0x64(%rbp)
  4960f7:	mov    -0x64(%rbp),%eax
  4960fa:	shl    $0x20,%rax
  4960fe:	mov    %rax,%rdx
  496101:	mov    -0x68(%rbp),%eax
  496104:	or     %rdx,%rax
  496107:	sub    -0x60(%rbp),%rax
  49610b:	mov    %rax,%rdx
  49610e:	mov    -0x88(%rbp),%rax
  496115:	mov    0x40(%rax),%rax
  496119:	add    %rax,%rdx
  49611c:	mov    -0x88(%rbp),%rax
  496123:	mov    %rdx,0x40(%rax)
  496127:	mov    -0x88(%rbp),%rax
  49612e:	mov    0x38(%rax),%rax
  496132:	lea    0x1(%rax),%rdx
  496136:	mov    -0x88(%rbp),%rax
  49613d:	mov    %rdx,0x38(%rax)
  496141:	mov    -0x88(%rbp),%rax
  496148:	mov    0x30(%rax),%rax
  49614c:	lea    0x1(%rax),%rdx
  496150:	mov    -0x88(%rbp),%rax
  496157:	mov    %rdx,0x30(%rax)
  49615b:	nop
  49615c:	mov    -0x18(%rbp),%rax
  496160:	xor    %fs:0x28,%rax
  496169:	je     496170 <RAMCloud::SpinLock::lock()+0x314>
  49616b:	callq  3080e0 <.plt.got+0x260>
  496170:	mov    -0x8(%rbp),%rbx
  496174:	leaveq 
  496175:	retq   
