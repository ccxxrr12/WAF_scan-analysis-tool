<!-- 每个回话对应的聊天内容 -->
<script setup lang="ts">
import type { AnyObject } from 'typescript-api-pro';
import type { BubbleProps } from 'vue-element-plus-x/types/Bubble';
import type { BubbleListInstance } from 'vue-element-plus-x/types/BubbleList';
import type { FilesCardProps } from 'vue-element-plus-x/types/FilesCard';
import type { ThinkingStatus } from 'vue-element-plus-x/types/Thinking';
import { useHookFetch } from 'hook-fetch/vue';
import { Sender } from 'vue-element-plus-x';
import { useRoute } from 'vue-router';
import { send, scanWaf, aiDetect, analyzeRules } from '@/api';
import FilesSelect from '@/components/FilesSelect/index.vue';
import ModelSelect from '@/components/ModelSelect/index.vue';

import { useChatStore } from '@/stores/modules/chat';
import { useFilesStore } from '@/stores/modules/files';
import { useModelStore } from '@/stores/modules/model';
import { useUserStore } from '@/stores/modules/user';
type MessageItem = BubbleProps & {
  key: number;
  role: 'ai' | 'user' | 'system';
  avatar: string;
  thinkingStatus?: ThinkingStatus;
  thinlCollapse?: boolean;
  reasoning_content?: string;
};

const route = useRoute();
const chatStore = useChatStore();
const modelStore = useModelStore();
const filesStore = useFilesStore();
const userStore = useUserStore();

// 用户头像
const avatar = computed(() => {
  const userInfo = userStore.userInfo;
  return userInfo?.avatar || 'https://avatars.githubusercontent.com/u/76239030?v=4';
});

const inputValue = ref('');
const senderRef = ref<InstanceType<typeof Sender> | null>(null);
const bubbleItems = ref<MessageItem[]>([]);
const bubbleListRef = ref<BubbleListInstance | null>(null);

const { stream, loading: isLoading, cancel } = useHookFetch({
  request: send,
  onError: (err) => {
    console.warn('测试错误拦截', err);
  },
});
// 记录进入思考中
let isThinking = false;

watch(
  () => route.params?.id,
  async (_id_) => {
    if (_id_) {
      if (_id_ !== 'not_login') {
        // 判断的当前会话id是否有聊天记录，有缓存则直接赋值展示
        if (chatStore.chatMap[`${_id_}`] && chatStore.chatMap[`${_id_}`].length) {
          bubbleItems.value = chatStore.chatMap[`${_id_}`] as MessageItem[];
          // 滚动到底部
          setTimeout(() => {
            bubbleListRef.value!.scrollToBottom();
          }, 350);
          return;
        }

        // 无缓存则请求聊天记录
        await chatStore.requestChatList(`${_id_}`);
        // 请求聊天记录后，赋值回显，并滚动到底部
        bubbleItems.value = chatStore.chatMap[`${_id_}`] as MessageItem[];

        // 滚动到底部
        setTimeout(() => {
          bubbleListRef.value!.scrollToBottom();
        }, 350);
      }

      // 如果本地有发送内容 ，则直接发送
      const v = localStorage.getItem('chatContent');
      if (v) {
        // 发送消息
        console.log('发送消息 v', v);
        setTimeout(() => {
          startSSE(v);
        }, 350);

        localStorage.removeItem('chatContent');
      }
    }
  },
  { immediate: true, deep: true },
);

// 封装数据处理逻辑
function handleDataChunk(chunk: AnyObject) {
  try {
    const reasoningChunk = chunk.choices?.[0].delta.reasoning_content;
    if (reasoningChunk) {
      // 开始思考链状态
      bubbleItems.value[bubbleItems.value.length - 1].thinkingStatus = 'thinking';
      bubbleItems.value[bubbleItems.value.length - 1].loading = true;
      bubbleItems.value[bubbleItems.value.length - 1].thinlCollapse = true;
      if (bubbleItems.value.length) {
        bubbleItems.value[bubbleItems.value.length - 1].reasoning_content += reasoningChunk;
      }
    }

    // 另一种思考中形式，content中有 <think></think> 的格式
    // 一开始匹配到 <think> 开始，匹配到 </think> 结束，并处理标签中的内容为思考内容
    const parsedChunk = chunk.choices?.[0].delta.content;
    if (parsedChunk) {
      const thinkStart = parsedChunk.includes('<think>');
      const thinkEnd = parsedChunk.includes('</think>');
      if (thinkStart) {
        isThinking = true;
      }
      if (thinkEnd) {
        isThinking = false;
      }
      if (isThinking) {
        // 开始思考链状态
        bubbleItems.value[bubbleItems.value.length - 1].thinkingStatus = 'thinking';
        bubbleItems.value[bubbleItems.value.length - 1].loading = true;
        bubbleItems.value[bubbleItems.value.length - 1].thinlCollapse = true;
        if (bubbleItems.value.length) {
          bubbleItems.value[bubbleItems.value.length - 1].reasoning_content += parsedChunk
            .replace('<think>', '')
            .replace('</think>', '');
        }
      }
      else {
        // 结束 思考链状态
        bubbleItems.value[bubbleItems.value.length - 1].thinkingStatus = 'end';
        bubbleItems.value[bubbleItems.value.length - 1].loading = false;
        if (bubbleItems.value.length) {
          bubbleItems.value[bubbleItems.value.length - 1].content += parsedChunk;
        }
      }
    }
  }
  catch (err) {
    // 这里如果使用了中断，会有报错，可以忽略不管
    console.error('解析数据时出错:', err);
  }
}

// 监听文件列表变化，实现上传后解除发送禁用
watch(
  () => filesStore.filesList.length,
  async (newLength, oldLength) => {
    if (newLength > oldLength) {
      // 有文件上传，解除发送禁用（通过添加一个空格字符）
      if (!inputValue.value.trim()) {
        inputValue.value = ' ';
      }
      
      // 检查是否有新上传的规则文件
      const uploadedFiles = filesStore.filesList;
      const ruleFiles = uploadedFiles.filter(file => 
        (file as any).name.endsWith('.conf') || 
        (file as any).name.endsWith('.txt') || 
        (file as any).name.endsWith('.rules')
      );
      
    }
    else if (newLength === 0 && inputValue.value === ' ') {
      // 没有文件上传且输入值是我们添加的空格，则清空输入值
      inputValue.value = '';
    }
  }
);

async function startSSE(chatContent: string) {
  try {
    // 检查是否有上传的文件
    const uploadedFiles = filesStore.filesList;
    const hasFiles = uploadedFiles.length > 0;
    
    // 只允许发送非空消息或有上传文件
    if (chatContent.trim() || hasFiles) {
      // 添加用户输入的消息
      inputValue.value = '';
      addMessage(chatContent, true);
      addMessage('', false);

      // 这里有必要调用一下 BubbleList 组件的滚动到底部 手动触发 自动滚动
      bubbleListRef.value?.scrollToBottom();

      // 检查是否有规则文件需要分析
      const ruleFiles = uploadedFiles.filter(file => 
        (file as any).name.endsWith('.conf') || 
        (file as any).name.endsWith('.txt') || 
        (file as any).name.endsWith('.rules')
      );
      
      if (ruleFiles.length > 0) {
        // 调用规则分析API
        await handleRuleAnalysis(ruleFiles);
      } else {
        // 智能判断输入类型
        const urlPattern = /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([\/\w .-]*)*\/?$/;
        const isUrlOnly = urlPattern.test(chatContent) && chatContent.split('\n').length === 1;
        
        if (isUrlOnly) {
          // 仅输入URL，调用Part1 WAF扫描API
          await handleWafScan(chatContent);
        } else if (chatContent.includes('http') && chatContent.includes('\n')) {
          // 包含URL和请求内容，调用Part3深度学习API
          await handleAIDetect(chatContent);
        } else {
          // 其他情况，使用原有AI聊天API
          for await (const chunk of stream({
            messages: bubbleItems.value
              .filter((item: any) => item.role === 'user')
              .map((item: any) => ({
                role: item.role,
                content: item.content,
              })),
            sessionId: route.params?.id !== 'not_login' ? String(route.params?.id) : undefined,
            userId: userStore.userInfo?.userId,
            model: modelStore.currentModelInfo.modelName ?? '',
          })) {
            handleDataChunk(chunk.result as AnyObject);
          }
        }
      }
      
      // 清空已上传的文件
      filesStore.clearFiles();
    }
  } catch (err) {
    console.error('发送消息失败:', err);
    // 确保有消息项来更新
    if (bubbleItems.value.length > 0) {
      const lastItem = bubbleItems.value[bubbleItems.value.length - 1];
      lastItem.content = `发送失败：${err instanceof Error ? err.message : String(err)}`;
      lastItem.loading = false;
      lastItem.thinkingStatus = 'end';
    }
  } finally {
    console.log('数据接收完毕');
    // 停止打字器状态
    if (bubbleItems.value.length) {
      bubbleItems.value[bubbleItems.value.length - 1].typing = false;
    }
  }
}

// 处理规则分析
async function handleRuleAnalysis(files: any[]) {
  try {
    let allResults = '';
    
    // 提取实际的File对象
    const actualFiles = files.map(fileItem => fileItem.file);
    
    // 获取会话ID
    const sessionId = route.params?.id || 'default';
    
    // 调用规则分析API，发送所有文件和会话ID
    const result = await analyzeRules(actualFiles as File[], String(sessionId));
    console.log('规则分析结果:', result);
    
    if (result.success) {
      const data = result.data || {};
      const analyzedFiles = data.files || [];
      
      // 1. 规则分析总结
      allResults += `### 规则分析总结\n`;
      allResults += `总规则数: ${data.total_rules || 0}\n`;
      allResults += `分析文件数: ${analyzedFiles.length}\n\n`;
      
      // 2. 每个文件的基本信息
      for (const fileResult of analyzedFiles) {
        allResults += `规则文件: ${fileResult.filename}\n`;
        allResults += `规则数量: ${fileResult.rule_count || 0}\n`;
        allResults += `处理时间: ${new Date(fileResult.processed_time || Date.now()).toLocaleString('zh-CN')}\n\n`;
      }
      
      // 3. 添加可视化图像展示
      allResults += `规则可视化分析\n`;
      allResults += `规则处理流程\n`;
      allResults += `<iframe src="/api/waf/visualizations/rule_processing_flow?sessionId=${sessionId}" width="100%" height="400px" frameborder="0" style="margin: 10px 0;" title="规则处理流程"></iframe>\n\n`;
      allResults += `攻击类型分布\n`;
      allResults += `<iframe src="/api/waf/visualizations/attack_type_distribution?sessionId=${sessionId}" width="100%" height="400px" frameborder="0" style="margin: 10px 0;" title="攻击类型分布"></iframe>\n\n`;
      allResults += `冲突分析\n`;
      allResults += `<iframe src="/api/waf/visualizations/conflict_analysis?sessionId=${sessionId}" width="100%" height="400px" frameborder="0" style="margin: 10px 0;" title="冲突分析"></iframe>\n\n`;
      
      // 4. 添加详细报告下载链接
      allResults += `\n详细报告\n`;
      allResults += `[下载详细规则报告 (Markdown格式)](/api/waf/reports/detailed_rules_report?sessionId=${sessionId})\n\n`;
    } else {
      allResults += `规则分析失败\n`;
      allResults += `错误信息：${result.error || '未知错误'}\n\n`;
    }
    
    // 更新聊天消息
    bubbleItems.value[bubbleItems.value.length - 1].content = allResults;
    // 更新消息状态
    bubbleItems.value[bubbleItems.value.length - 1].loading = false;
    bubbleItems.value[bubbleItems.value.length - 1].thinkingStatus = 'end';
  } catch (error) {
    console.error('规则分析失败:', error);
    bubbleItems.value[bubbleItems.value.length - 1].content = `规则分析失败：${error instanceof Error ? error.message : '未知错误'}`;
    bubbleItems.value[bubbleItems.value.length - 1].loading = false;
    bubbleItems.value[bubbleItems.value.length - 1].thinkingStatus = 'end';
  }
}

// 处理WAF扫描
async function handleWafScan(url: string) {
  try {
    // 获取会话ID
    const sessionId = route.params?.id || 'default';
    const response = await scanWaf({ url }, String(sessionId));
    console.log('WAF扫描响应:', response);
    
    // Get the correct result structure based on hook-fetch behavior
    let result;
    if (response && typeof response === 'object') {
      // Check different possible response structures
      if ('data' in response) {
        result = response.data;
      }
    }
    
    console.log('提取的结果:', result);
    
    const scanResult = result as any;
    if (scanResult?.detected) {
      let wafNames = scanResult.wafs?.map((waf: any) => `${waf.name} (${waf.manufacturer})`).join('、') || '未知';
      let content = `检测到WAF防护：\n${wafNames}\n\n详细信息：\n- 检测到${scanResult.wafs?.length || 0}种WAF\n- 发送请求数：${scanResult.request_count || 0}`;
      bubbleItems.value[bubbleItems.value.length - 1].content = content;
    } else {
      let content = `未检测到WAF防护\n\n详细信息：\n- 发送请求数：${scanResult?.request_count || 0}`;
      bubbleItems.value[bubbleItems.value.length - 1].content = content;
    }
    // 更新消息状态
    bubbleItems.value[bubbleItems.value.length - 1].loading = false;
    bubbleItems.value[bubbleItems.value.length - 1].thinkingStatus = 'end';
  } catch (error) {
    console.error('WAF扫描失败:', error);
    bubbleItems.value[bubbleItems.value.length - 1].content = `WAF扫描失败：${error instanceof Error ? error.message : '未知错误'}`;
    bubbleItems.value[bubbleItems.value.length - 1].loading = false;
    bubbleItems.value[bubbleItems.value.length - 1].thinkingStatus = 'end';
  }
}

// 处理AI检测
async function handleAIDetect(chatContent: string) {
  try {
    // 提取URL和请求内容
    const lines = chatContent.split('\n');
    const url = lines[0].trim();
    const requestContent = lines.slice(1).join('\n').trim();
    
    // 获取会话ID
    const sessionId = route.params?.id || 'default';
    const responseResult = await aiDetect({ url, request_content: requestContent }, String(sessionId));
    console.log('AI检测响应:', responseResult);
    
    // Get the correct result structure based on hook-fetch behavior
    let result;
    if (responseResult && typeof responseResult === 'object') {
      if ('data' in responseResult) {
        result = responseResult.data;
      }
    }
    
    console.log('提取的AI检测结果:', result);
    
    const aiResult = result as any;
    if (aiResult) {
      let content = `AI检测结果：\n\nURL：${aiResult.url || url}\n预测结果：${aiResult.prediction === 'blocked' ? '拦截' : '放行'}\n置信度：${aiResult.confidence ? (aiResult.confidence * 100).toFixed(2) : '0.00'}%\n\n请求内容：\n${aiResult.request_content || requestContent}`;
      bubbleItems.value[bubbleItems.value.length - 1].content = content;
    } else {
      bubbleItems.value[bubbleItems.value.length - 1].content = `AI检测失败：无法获取结果`;
    }
    // 更新消息状态
    bubbleItems.value[bubbleItems.value.length - 1].loading = false;
    bubbleItems.value[bubbleItems.value.length - 1].thinkingStatus = 'end';
  } catch (error) {
    console.error('AI检测失败:', error);
    bubbleItems.value[bubbleItems.value.length - 1].content = `AI检测失败：${error instanceof Error ? error.message : '未知错误'}`;
    bubbleItems.value[bubbleItems.value.length - 1].loading = false;
    bubbleItems.value[bubbleItems.value.length - 1].thinkingStatus = 'end';
  }
}

// 中断请求
async function cancelSSE() {
  cancel();
  // 结束最后一条消息打字状态
  if (bubbleItems.value.length) {
    bubbleItems.value[bubbleItems.value.length - 1].typing = false;
  }
}

// 添加消息 - 维护聊天记录
function addMessage(message: string, isUser: boolean) {
  const i = bubbleItems.value.length;
  const obj: MessageItem = {
    key: i,
    avatar: isUser
      ? avatar.value
      : 'https://cube.elemecdn.com/0/88/03b0d39583f48206768a7534e55bcpng.png',
    avatarSize: '32px',
    role: isUser ? 'user' : 'system',
    placement: isUser ? 'end' : 'start',
    isMarkdown: !isUser,
    loading: !isUser,
    content: message || '',
    reasoning_content: '',
    thinkingStatus: 'start',
    thinlCollapse: false,
    noStyle: !isUser,
  };
  bubbleItems.value.push(obj);
}

// 展开收起 事件展示
function handleChange(payload: { value: boolean; status: ThinkingStatus }) {
  console.log('value', payload.value, 'status', payload.status);
}

function handleDeleteCard(_item: FilesCardProps, index: number) {
  filesStore.deleteFileByIndex(index);
}

watch(
  () => filesStore.filesList.length,
  (val) => {
    if (val > 0) {
      nextTick(() => {
        senderRef.value?.openHeader();
      });
    }
    else {
      nextTick(() => {
        senderRef.value?.closeHeader();
      });
    }
  },
);
</script>

<template>
  <div class="chat-with-id-container">
    <div class="chat-warp">
      <BubbleList ref="bubbleListRef" :list="bubbleItems" max-height="calc(100vh - 240px)">
        <template #header="{ item }">
          <Thinking
            v-if="item.reasoning_content" v-model="item.thinlCollapse" :content="item.reasoning_content"
            :status="item.thinkingStatus" class="thinking-chain-warp" @change="handleChange"
          />
        </template>

        <template #content="{ item }">
          <!-- chat 内容走 markdown -->
          <XMarkdown v-if="item.content && item.role === 'system'" :markdown="item.content" class="markdown-body" :themes="{ light: 'github-light', dark: 'github-dark' }" default-theme-mode="dark" />
          <!-- user 内容 纯文本 -->
          <div v-if="item.content && item.role === 'user'" class="user-content">
            {{ item.content }}
          </div>
        </template>
      </BubbleList>

      <Sender
        ref="senderRef" v-model="inputValue" class="chat-defaul-sender" :auto-size="{
          maxRows: 6,
          minRows: 2,
        }" variant="updown" clearable allow-speech :loading="isLoading" @submit="startSSE" @cancel="cancelSSE"
      >
        <template #header>
          <div class="sender-header p-12px pt-6px pb-0px">
            <Attachments :items="filesStore.filesList" :hide-upload="true" @delete-card="handleDeleteCard">
              <template #prev-button="{ show, onScrollLeft }">
                <div
                  v-if="show"
                  class="prev-next-btn left-8px flex-center w-22px h-22px rounded-8px border-1px border-solid border-[rgba(0,0,0,0.08)] c-[rgba(0,0,0,.4)] hover:bg-#f3f4f6 bg-#fff font-size-10px"
                  @click="onScrollLeft"
                >
                  <el-icon>
                    <ArrowLeftBold />
                  </el-icon>
                </div>
              </template>

              <template #next-button="{ show, onScrollRight }">
                <div
                  v-if="show"
                  class="prev-next-btn right-8px flex-center w-22px h-22px rounded-8px border-1px border-solid border-[rgba(0,0,0,0.08)] c-[rgba(0,0,0,.4)] hover:bg-#f3f4f6 bg-#fff font-size-10px"
                  @click="onScrollRight"
                >
                  <el-icon>
                    <ArrowRightBold />
                  </el-icon>
                </div>
              </template>
            </Attachments>
          </div>
        </template>
        <template #prefix>
          <div class="flex-1 flex items-center gap-8px flex-none w-fit overflow-hidden">
            <FilesSelect />
            <ModelSelect />
          </div>
        </template>
      </Sender>
    </div>
  </div>
</template>

<style scoped lang="scss">
.chat-with-id-container {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 100%;
  max-width: 800px;
  height: 100%;
  .chat-warp {
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    width: 100%;
    height: calc(100vh - 60px);
    .thinking-chain-warp {
      margin-bottom: 12px;
    }
  }
  :deep() {
    .el-bubble-list {
      padding-top: 24px;
    }
    .el-bubble {
      padding: 0 12px;
      padding-bottom: 24px;
    }
    .el-typewriter {
      overflow: hidden;
      border-radius: 12px;
    }
    .user-content {
      // 换行
      white-space: pre-wrap;
    }
    .markdown-body {
      background-color: transparent;
    }
    .markdown-elxLanguage-header-div {
      top: -25px !important;
    }

    // xmarkdown 样式
    .elx-xmarkdown-container {
      padding: 8px 4px;
    }
  }
  .chat-defaul-sender {
    width: 100%;
    margin-bottom: 22px;
  }
}
</style>
