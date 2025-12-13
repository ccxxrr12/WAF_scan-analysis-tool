import { ref } from 'vue';
import { defineStore } from 'pinia';

// 定义模式类型
export type AppMode = 'chat' | 'solo';

// 模式管理
export const useModeStore = defineStore('mode', () => {
  // 当前模式
  const currentMode = ref<AppMode>('chat');

  // 设置当前模式
  const setCurrentMode = (mode: AppMode) => {
    currentMode.value = mode;
  };

  // 切换模式
  const toggleMode = () => {
    currentMode.value = currentMode.value === 'chat' ? 'solo' : 'chat';
  };

  return {
    currentMode,
    setCurrentMode,
    toggleMode,
  };
});