kHypervisor: https://github.com/Kelvinhack/kHypervisor

### v1.0
基于kHypervisor框架添加了Msr/Ept Hook，仅用于学习和示例使用。

**see directory: kHypervisor/kHypervisor**

### v2.0(待开发)
根据Kelvinhack建议，可以尝试将khypervisor分离设计hv_lib接口
```
|-- hv 
  |-- nested hv
  |-- pci device mon
  |-- ept
  	|-- ept hook
...
```
**see directory: kHypervisor/kHypervisorBasic**
