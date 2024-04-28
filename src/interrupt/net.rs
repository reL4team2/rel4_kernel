use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use core::ptr::NonNull;
use axi_dma::{AxiDma, AxiDmaConfig, BufPtr};
use axi_ethernet::{AxiEthernet, LinkStatus, XAE_BROADCAST_OPTION, XAE_JUMBO_OPTION, XAE_MAX_JUMBO_FRAME_SIZE};
use log::debug;
use spin::{Lazy, Mutex};
use crate::common::sel4_config::PPTR_BASE_OFFSET;
use crate::vspace::{kpptr_to_paddr, pptr_to_paddr};

pub const ETH_ADDRESS: usize = 0x6014_0000 + PPTR_BASE_OFFSET;
pub const DMA_ADDRESS: usize = 0x6010_0000 + PPTR_BASE_OFFSET;
pub const MAC_ADDRESS: [u8; 6] = [0x00, 0x0A, 0x35, 0x01, 0x02, 0x03];

pub const AXI_DMA_CONFIG: AxiDmaConfig = AxiDmaConfig {
    base_address: DMA_ADDRESS,
    has_sts_cntrl_strm: false,
    is_micro_dma: false,
    has_mm2s: true,
    has_mm2s_dre: false,
    mm2s_data_width: 64,
    mm2s_burst_size: 16,
    has_s2mm: true,
    has_s2mm_dre: false,
    s2mm_data_width: 64,
    s2mm_burst_size: 16,
    has_sg: true,
    sg_length_width: 16,
    addr_width: 64,
    rx_channel_offset: 0,
    tx_channel_offset: 0,
};

pub struct AxiNetConfig {
    pub tx_bd_cnt: usize,
    pub rx_bd_cnt: usize,
    pub eth_baseaddr: usize,
    pub dma_baseaddr: usize,
    pub mac_addr: [u8; 6],
    pub mtu: usize
}

pub const AXI_NET_CONFIG: AxiNetConfig = AxiNetConfig {
    tx_bd_cnt: 1024,
    rx_bd_cnt: 1024,
    eth_baseaddr: ETH_ADDRESS,
    dma_baseaddr: DMA_ADDRESS,
    mac_addr: MAC_ADDRESS,
    mtu: XAE_MAX_JUMBO_FRAME_SIZE,
};

pub static AXI_DMA: Lazy<Arc<AxiDma>> = Lazy::new(|| Arc::new(AxiDma::new(AXI_DMA_CONFIG)));

pub static AXI_ETH: Lazy<Arc<Mutex<AxiEthernet>>> = Lazy::new(||  Arc::new(Mutex::new(AxiEthernet::new(
    AXI_NET_CONFIG.eth_baseaddr, AXI_NET_CONFIG.dma_baseaddr
))));

pub fn net_init() {
    dma_init();
    eth_init();
}

pub fn dma_init() {
    AXI_DMA.reset().unwrap();
    // enable cyclic mode
    AXI_DMA.cyclic_enable();

    // init cyclic block descriptor
    let _ = AXI_DMA.tx_channel_create_with_translate(AXI_NET_CONFIG.tx_bd_cnt, kpptr_to_paddr).unwrap();
    let _ = AXI_DMA.rx_channel_create_with_translate(AXI_NET_CONFIG.rx_bd_cnt, kpptr_to_paddr).unwrap();
    AXI_DMA.intr_enable();
}


pub fn eth_init() {
    let mut eth = AXI_ETH.lock();
    eth.reset();
    let options = eth.get_options();
    eth.set_options(options | XAE_JUMBO_OPTION);
    eth.clear_options(XAE_BROADCAST_OPTION);
    eth.detect_phy();
    let speed = eth.get_phy_speed_ksz9031();
    debug!("speed is: {}", speed);
    eth.set_operating_speed(speed as u16);
    if speed == 0 {
        eth.link_status = LinkStatus::EthLinkDown;
    } else {
        eth.link_status = LinkStatus::EthLinkUp;
    }
    eth.set_mac_address(&AXI_NET_CONFIG.mac_addr);
    debug!("link_status: {:?}", eth.link_status);
    eth.enable_rx_memovr();
    eth.clear_rx_memovr();
    eth.enable_rx_rject();
    eth.clear_rx_rject();
    eth.enable_rx_cmplt();
    eth.clear_rx_cmplt();
    eth.clear_tx_cmplt();

    eth.start();
}

pub fn eth_recv() {
    debug!("eth_recv");
    let mut local_eth = AXI_ETH.lock();
    if local_eth.can_receive() {
        let mtu = 1514;
        let buffer = vec![1u8; mtu].into_boxed_slice();
        let len = buffer.len();
        let tmp = Box::into_raw(buffer) as *mut usize as usize;
        let buf_ptr: *mut u8 = kpptr_to_paddr(tmp) as *mut _;
        debug!("tmp: {:#x}, {:#x}", tmp, buf_ptr as usize);
        let buf = BufPtr::new(NonNull::new(buf_ptr).unwrap(), len);
        let mut rbuf = AXI_DMA
            .rx_submit_with_translate(buf, kpptr_to_paddr)
            .unwrap()
            .wait()
            .unwrap();
        debug!("recev end0");
        let buf = unsafe { core::slice::from_raw_parts_mut(rbuf.as_mut_ptr(), rbuf.len()) };
        let _box_buf = unsafe { Box::from_raw(buf) };
    } else {
        debug!("cannot receive");
    }
    if local_eth.is_rx_cmplt() {
        local_eth.clear_rx_cmplt();
    }
    if local_eth.is_tx_cmplt() {
        local_eth.clear_tx_cmplt();
    }
}