# REPOSITORY STANDARD
## 1.文件架构组织方式
* 项目分为三个模块，每个模块单独建立一个文件夹，命名为pn
    * 数据文件名`data_type_name`
    * 模块目录必须包含目录： `bin`，必要的依赖关系 `lib`，`plugins`
    * 模块目录必须包含文件：项目说明文档`readme.md`，开源协议文档`LICENSE`
## 2.代码提交要求
* 如若提交内容与仓库内容无冲突，提交时间无冲突，直接push到main branch
* 若存在任一冲突，个人单独建立一个branch，向`sherry`发送pull request并附冲突内容
## 3.代码规范
* 同一模块开发时内部统一命名准则
* 对于全局变量、函数，使用`GBK`或者`GB2312`提供详细的中文注释