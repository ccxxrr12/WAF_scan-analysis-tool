<!-- 模式切换组件 -->
<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useModeStore } from '@/stores/modules/mode';

// 定义模式类型
type Mode = 'chat' | 'solo';

// 组件属性
const props = defineProps<{
  // 尺寸，默认与ModelSelect组件一致
  size?: string;
}>();

// 事件
const emit = defineEmits<{
  // 模式变化事件
  'change': [mode: Mode];
}>();

// 使用模式store
const modeStore = useModeStore();

// 当前模式
const currentMode = computed(() => modeStore.currentMode);

// 切换模式
const toggleMode = () => {
  modeStore.toggleMode();
  emit('change', modeStore.currentMode);
};

// 计算滑块位置
const sliderPosition = computed(() => {
  return currentMode.value === 'chat' ? '0%' : '50%';
});

// 计算显示的模式名称
const displayMode = computed(() => {
  return currentMode.value;
});
</script>

<template>
  <div class="mode-toggle" @click="toggleMode">
    <div class="mode-toggle-container" :class="{ 'chat-mode': currentMode === 'chat', 'solo-mode': currentMode === 'solo' }">
      <div class="mode-toggle-slider"></div>
      <div class="mode-toggle-labels">
        <span class="mode-toggle-label chat-label" :class="{ active: currentMode === 'chat' }">
          chat
        </span>
        <span class="mode-toggle-label solo-label" :class="{ active: currentMode === 'solo' }">
          solo
        </span>
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
.mode-toggle {
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.mode-toggle-container {
  position: relative;
  width: 80px;
  height: 32px;
  background-color: var(--el-color-primary-light-9, rgb(235.9 245.3 255));
  border: 1px solid var(--el-color-primary, #409eff);
  border-radius: 16px;
  overflow: hidden;
  transition: all 0.2s ease;
}

.mode-toggle-slider {
  position: absolute;
  top: 1px;
  left: 1px;
  width: 30px;
  height: 30px;
  background-color: var(--el-color-primary, #409eff);
  border-radius: 50%;
  transition: left 0.2s ease;
  z-index: 2;
}

.mode-toggle-container.chat-mode .mode-toggle-slider {
  left: 1px;
}

.mode-toggle-container.solo-mode .mode-toggle-slider {
  left: 49px;
}

.mode-toggle-labels {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  display: flex;
  align-items: center;
  justify-content: space-around;
  z-index: 1;
}

.mode-toggle-label {
  font-size: 12px;
  font-weight: 500;
  transition: all 0.3s ease;
  opacity: 0;
}

.mode-toggle-label.chat-label {
  margin-right: 50%;
  color: var(--el-color-primary, #409eff);
}

.mode-toggle-label.solo-label {
  margin-left: 50%;
  color: var(--el-color-primary, #409eff);
}

.mode-toggle-label.active {
  opacity: 1;
}

.mode-toggle:hover .mode-toggle-container {
  background-color: var(--el-color-primary-light-8, rgb(224.7 242.0 255));
}

.mode-toggle:hover .mode-toggle-slider {
  background-color: var(--el-color-primary-light-7, rgb(194.3 233.9 255));
}
</style>