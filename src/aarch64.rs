use core::arch::asm;

#[inline]
pub fn set_kernel_stack(stack_address: usize) {
	#[cfg(feature = "ARM_HYPERVISOR_SUPPORT")]
	{
		// TODO
	}
	#[cfg(not(feature = "ARM_HYPERVISOR_SUPPORT"))]
	{
		writeTPIDR_EL1(stack_address)
	}
}
pub fn writeTPIDR_EL1(reg: usize){
	asm!(
		"msr tpidr_el1,{}",
		inreg(reg),
	);
}