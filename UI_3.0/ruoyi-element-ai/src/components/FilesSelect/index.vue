<!-- 文件上传 -->
<script setup lang="ts">
import type { FilesCardProps } from 'vue-element-plus-x/types/FilesCard';
import { useFileDialog } from '@vueuse/core';
import { ElMessage } from 'element-plus';
import Popover from '@/components/Popover/index.vue';
import SvgIcon from '@/components/SvgIcon/index.vue';
import { useFilesStore } from '@/stores/modules/files';

type FilesList = FilesCardProps & {
  file: File;
};

const filesStore = useFilesStore();

/* 弹出面板 开始 */
const popoverStyle = ref({
  padding: '4px',
  height: 'fit-content',
  background: 'var(--el-bg-color, #fff)',
  border: '1px solid var(--el-border-color-light)',
  borderRadius: '8px',
  boxShadow: '0 2px 12px 0 rgba(0, 0, 0, 0.1)',
});
const popoverRef = ref();
/* 弹出面板 结束 */

// 普通文件上传
const { reset: resetFiles, open: openFiles, onChange: onChangeFiles } = useFileDialog({
  // 允许所有图片文件，文档文件，音视频文件
  accept: 'image/*,video/*,audio/*,application/*',
  directory: false, // 是否允许选择文件夹
  multiple: true, // 是否允许多选
});

// 规则文件上传
const { reset: resetRuleFiles, open: openRuleFiles, onChange: onChangeRuleFiles } = useFileDialog({
  // 允许配置文件和文本文件
  accept: '.conf,.txt,.rules,application/*',
  directory: false,
  multiple: true,
});

// 规则文件夹上传
const { reset: resetRuleFolder, open: openRuleFolder, onChange: onChangeRuleFolder } = useFileDialog({
  directory: true,
  multiple: false,
});

// 处理普通文件上传
onChangeFiles((files) => {
  if (!files)
    return;
  const arr = [] as FilesList[];
  for (let i = 0; i < files!.length; i++) {
    const file = files![i];
    arr.push({
      uid: crypto.randomUUID(),
      name: file.name,
      fileSize: file.size,
      file,
      maxWidth: '200px',
      showDelIcon: true,
      imgPreview: true,
      imgVariant: 'square',
      url: URL.createObjectURL(file),
    });
  }
  filesStore.setFilesList([...filesStore.filesList, ...arr]);
  nextTick(() => resetFiles());
});

// 处理规则文件上传
onChangeRuleFiles((files) => {
  if (!files)
    return;
  const arr = [] as FilesList[];
  for (let i = 0; i < files!.length; i++) {
    const file = files![i];
    arr.push({
      uid: crypto.randomUUID(),
      name: file.name,
      fileSize: file.size,
      file,
      maxWidth: '200px',
      showDelIcon: true,
      imgPreview: false,
      imgVariant: 'square',
      url: URL.createObjectURL(file),
    });
  }
  filesStore.setFilesList([...filesStore.filesList, ...arr]);
  nextTick(() => resetRuleFiles());
});

// 处理规则文件夹上传
onChangeRuleFolder((entries) => {
  if (!entries)
    return;
  
  // 处理文件夹上传
  const processEntries = async () => {
    const arr = [] as FilesList[];
    
    // 递归处理文件夹条目
    const processEntry = async (entry: FileSystemFileEntry | FileSystemDirectoryEntry) => {
      if (entry.isFile) {
        // 处理文件
        const file = await new Promise<File>((resolve) => {
          (entry as FileSystemFileEntry).file(resolve);
        });
        // 只添加规则相关文件
        if (file.name.endsWith('.conf') || file.name.endsWith('.txt') || file.name.endsWith('.rules')) {
          arr.push({
            uid: crypto.randomUUID(),
            name: file.name,
            fileSize: file.size,
            file,
            maxWidth: '200px',
            showDelIcon: true,
            imgPreview: false,
            imgVariant: 'square',
            url: URL.createObjectURL(file),
          });
        }
      } else if (entry.isDirectory) {
        // 处理子目录
        const reader = (entry as FileSystemDirectoryEntry).createReader();
        const subEntries = await new Promise<FileSystemEntry[]>((resolve) => {
          reader.readEntries(resolve);
        });
        // 递归处理所有子条目
        for (const subEntry of subEntries) {
          await processEntry(subEntry);
        }
      }
    };
    
    // 处理所有选中的条目
    for (const entry of entries as any) {
      await processEntry(entry);
    }
    
    // 添加到文件列表
    filesStore.setFilesList([...filesStore.filesList, ...arr]);
    nextTick(() => resetRuleFolder());
  };
  
  processEntries().catch((error) => {
    console.error('处理文件夹上传失败:', error);
    ElMessage.error('处理文件夹上传失败');
  });
});

function handleUploadFiles() {
  openFiles();
  popoverRef.value.hide();
}

// 处理规则文件上传
function handleUploadRuleFiles() {
  openRuleFiles();
  popoverRef.value.hide();
}

// 处理规则文件夹上传
function handleUploadRuleFolder() {
  openRuleFolder();
  popoverRef.value.hide();
}
</script>

<template>
  <div class="files-select">
    <Popover
      ref="popoverRef"
      placement="top-start"
      :offset="[4, 0]"
      popover-class="popover-content"
      :popover-style="popoverStyle"
      trigger="clickTarget"
    >
      <template #trigger>
        <div
          class="flex items-center gap-4px p-10px rounded-10px cursor-pointer font-size-14px border-1px border-[rgba(0,0,0,0.08)] border-solid hover:bg-[rgba(0,0,0,.04)]"
        >
          <el-icon>
            <Paperclip />
          </el-icon>
        </div>
      </template>

      <div class="popover-content-box">
        <div
          class="popover-content-item flex items-center gap-4px p-10px rounded-10px cursor-pointer font-size-14px hover:bg-[rgba(0,0,0,.04)]"
          @click="handleUploadFiles"
        >
          <el-icon>
            <Upload />
          </el-icon>
          <div class="font-size-14px">
            上传文件或图片
          </div>
        </div>

        <!-- 规则上传子菜单 -->
        <Popover
          placement="right-end"
          :offset="[8, 4]"
          popover-class="popover-content"
          :popover-style="popoverStyle"
          trigger="hover"
          :hover-delay="100"
        >
          <template #trigger>
            <div
              class="popover-content-item flex items-center gap-4px p-10px rounded-10px cursor-pointer font-size-14px hover:bg-[rgba(0,0,0,.04)]"
            >
              <el-icon>
                <DocumentChecked />
              </el-icon>
              <div class="font-size-14px">
                上传规则
              </div>

              <el-icon class="ml-auto">
                <ArrowRight />
              </el-icon>
            </div>
          </template>

          <div class="popover-content-box">
            <div
              class="popover-content-item flex items-center gap-4px p-10px rounded-10px cursor-pointer font-size-14px hover:bg-[rgba(0,0,0,.04)]"
              @click="handleUploadRuleFiles"
            >
              <el-icon>
                <Document />
              </el-icon>
              规则文件
            </div>

            <div
              class="popover-content-item flex items-center gap-4px p-10px rounded-10px cursor-pointer font-size-14px hover:bg-[rgba(0,0,0,.04)]"
              @click="handleUploadRuleFolder"
            >
              <el-icon>
                <FolderOpened />
              </el-icon>
              规则文件夹
            </div>
          </div>
        </Popover>

        <!-- 代码上传子菜单 (保持原有功能) -->
        <Popover
          placement="right-end"
          :offset="[8, 4]"
          popover-class="popover-content"
          :popover-style="popoverStyle"
          trigger="hover"
          :hover-delay="100"
        >
          <template #trigger>
            <div
              class="popover-content-item flex items-center gap-4px p-10px rounded-10px cursor-pointer font-size-14px hover:bg-[rgba(0,0,0,.04)]"
            >
              <SvgIcon name="code" size="16" />
              <div class="font-size-14px">
                上传代码
              </div>

              <el-icon class="ml-auto">
                <ArrowRight />
              </el-icon>
            </div>
          </template>

          <div class="popover-content-box">
            <div
              class="popover-content-item flex items-center gap-4px p-10px rounded-10px cursor-pointer font-size-14px hover:bg-[rgba(0,0,0,.04)]"
              @click="
                () => {
                  ElMessage.warning('暂未开放');
                }
              "
            >
              代码文件
            </div>

            <div
              class="popover-content-item flex items-center gap-4px p-10px rounded-10px cursor-pointer font-size-14px hover:bg-[rgba(0,0,0,.04)]"
              @click="
                () => {
                  ElMessage.warning('暂未开放');
                }
              "
            >
              代码文件夹
            </div>
          </div>
        </Popover>
      </div>
    </Popover>
  </div>
</template>

<style scoped lang="scss"></style>
