<!-- Main -->
<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { useDesignStore } from '@/stores';
import { useKeepAliveStore } from '@/stores/modules/keepAlive';
import { useModeStore } from '@/stores/modules/mode';

const designStore = useDesignStore();
const keepAliveStore = useKeepAliveStore();
const useroute = useRoute();
const modeStore = useModeStore();

// 页面切换动画
const transitionName = computed(() => {
  return 'zoom-fade'; // 使用统一的缩放淡入淡出动画
});

// 刷新当前路由页面缓存方法
const isRouterShow = ref(true);
const refreshMainPage = (val: boolean) => (isRouterShow.value = val);
provide('refresh', refreshMainPage);

// 用于快速切换的iframe ref
const soloIframe = ref<HTMLIFrameElement | null>(null);
</script>

<template>
  <el-main
    class="layout-main"
    :class="{ 'layout-main-overfow-hidden': useroute.meta.isDefaultChat }"
  >
    <transition :name="transitionName" mode="out-in" appear>
      <!-- 模式切换内容 -->
      <div v-if="modeStore.currentMode === 'chat'" class="main-content">
        <router-view v-slot="{ Component, route }">
          <keep-alive :max="10" :include="keepAliveStore.keepAliveName">
            <component :is="Component" v-if="isRouterShow" :key="route.fullPath" />
          </keep-alive>
        </router-view>
      </div>
      <div v-else class="solo-mode-container">
        <iframe 
          ref="soloIframe"
          src="/index.html" 
          class="solo-mode-iframe" 
          frameborder="0"
          title="WAF Solo Mode"
          preload
        ></iframe>
      </div>
    </transition>
  </el-main>
</template>

<style scoped lang="scss">
.layout-main {
  position: relative;
  width: 100%;
  height: 100%;
  overflow: hidden;
}

.layout-main-overfow-hidden {
  overflow: hidden;
}

/* 主内容区域 */
.main-content {
  width: 100%;
  height: 100%;
  overflow: auto;
}

/* Solo模式容器 */
.solo-mode-container {
  width: 100%;
  height: 100%;
  overflow: hidden;
}

/* Solo模式iframe */
.solo-mode-iframe {
  width: 100%;
  height: 100%;
  border: none;
}

/* 默认聊天页面：上下滑动动画 */
.slide-enter-from {
  margin-top: 200px;
  opacity: 0;
}
.slide-enter-active,
.slide-leave-active {
  transition: all 0.3s ease; /* 缓出动画 */
}
.slide-enter-to {
  margin-top: 0;
  opacity: 1;
}
.slide-leave-from {
  margin-top: 0;
  opacity: 1;
}
.slide-leave-to {
  margin-top: 200px;
  opacity: 0;
}

/* 带id聊天页面：中间缩放动画 */
// .zoom-fade-enter-from {
//   transform: scale(0.9); /* 进入前：缩小隐藏 */
//   opacity: 0;
// }
// .zoom-fade-enter-active,
// .zoom-fade-leave-active {
//   transition: all 0.3s ease; /* 缓入动画 */
// }
// .zoom-fade-enter-to {
//   transform: scale(1); /* 进入后：正常大小 */
//   opacity: 1;
// }
// .zoom-fade-leave-from {
//   transform: scale(1); /* 离开前：正常大小 */
//   opacity: 1;
// }
// .zoom-fade-leave-to {
//   transform: scale(0.9); /* 离开后：缩小隐藏 */
//   opacity: 0;
// }

/* 启用缩放淡入淡出动画 */
.zoom-fade-enter-from {
  opacity: 0;
  transform: scale(0.95);
}

.zoom-fade-enter-active,
.zoom-fade-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
  will-change: opacity, transform;
}

.zoom-fade-enter-to,
.zoom-fade-leave-from {
  opacity: 1;
  transform: scale(1);
}

.zoom-fade-leave-to {
  opacity: 0;
  transform: scale(0.95);
}
</style>
