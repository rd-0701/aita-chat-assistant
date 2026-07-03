const FormData = require('form-data');
const axios = require('axios');

async function test() {
    console.log('Testing new analysis with both-side chat...\n');
    const form = new FormData();
    // 包含双方对话的测试内容
    form.append('chatContent', '【我】: 嗨，最近忙啥呢？好久没找你聊天了哈哈\n【对方】: 哎呀最近在赶一个项目，天天加班到好晚😭\n【我】: 卧槽这么惨？要注意身体啊兄弟，别猝死了\n【对方】: 哈哈哈放心放心，我扛得住！你呢最近咋样\n【我】: 我还行吧，就是有点无聊，周末想找点事做\n【对方】: 要不周末一起出去玩？我听说城东新开了个超棒的咖啡馆\n【我】: 可以啊！你什么时候有空\n【对方】: 周六下午呗，我上午有事\n【我】: 行，那就周六下午，到时候你发我定位\n【对方】: okk！期待期待');
    form.append('userInfo', JSON.stringify({}));

    try {
        const resp = await axios.post('http://localhost:3001/api/analyze', form, {
            headers: form.getHeaders(),
            timeout: 300000,
            maxContentLength: Infinity,
            maxBodyLength: Infinity
        });
        console.log('=== HTTP Status:', resp.status, '===');
        console.log('=== success:', resp.data.success, '===\n');

        if (resp.data.analysis) {
            const a = resp.data.analysis;
            // 1. 提取的聊天记录
            console.log('=== 提取的聊天记录（前300字）===');
            console.log(a.extractedMessages ? a.extractedMessages.substring(0, 300) : '(空)');
            console.log('');

            // 2. 人格画像
            if (a.personalityProfile) {
                console.log('=== 人格画像 overview ===');
                console.log(a.personalityProfile.overview || '(空)');
                console.log('');
                if (a.personalityProfile.relationshipStatus) {
                    console.log('=== 关系阶段 ===');
                    console.log(a.personalityProfile.relationshipStatus);
                    console.log('');
                }
            }

            // 3. MBTI
            if (a.mbti) {
                console.log('=== MBTI type:', a.mbti.type, '===');
                if (a.mbti.dimensionAnalysis) {
                    const da = a.mbti.dimensionAnalysis;
                    console.log('  E_I: direction=' + (da.E_I&&da.E_I.direction) + ' score=' + (da.E_I&&da.E_I.score));
                    console.log('  S_N: direction=' + (da.S_N&&da.S_N.direction) + ' score=' + (da.S_N&&da.S_N.score));
                    console.log('  T_F: direction=' + (da.T_F&&da.T_F.direction) + ' score=' + (da.T_F&&da.T_F.score));
                    console.log('  J_P: direction=' + (da.J_P&&da.J_P.direction) + ' score=' + (da.J_P&&da.J_P.score));
                    // 验证一致性
                    const type = a.mbti.type || '';
                    const dirs = [
                        da.E_I && da.E_I.direction,
                        da.S_N && da.S_N.direction,
                        da.T_F && da.T_F.direction,
                        da.J_P && da.J_P.direction
                    ].join('');
                    console.log('  4个direction组合:', dirs, type === dirs ? '✓与type一致' : '✗与type不一致!');
                }
                console.log('');
            }

            // 4. 聊天建议
            if (a.chatSuggestion) {
                const cs = a.chatSuggestion;
                console.log('=== 聊天建议 ===');
                if (cs.userStyleAnalysis) {
                    console.log('[用户语气分析]:', cs.userStyleAnalysis);
                }
                if (cs.conversationAnalysis) {
                    console.log('[聊天状态分析]:', cs.conversationAnalysis);
                }
                if (cs.suggestions && cs.suggestions.length > 0) {
                    console.log('\n[建议话术]:');
                    cs.suggestions.forEach((s, i) => {
                        console.log(`  ${i+1}. [${s.type}] ${s.message}`);
                    });
                }
                console.log('');
            }

            console.log('=== TEST PASSED ===');
        } else if (resp.data.message) {
            console.log('=== message:', resp.data.message, '===');
        }
    } catch (err) {
        console.log('=== ERROR ===');
        console.log(err.message);
        if (err.response) {
            console.log('Status:', err.response.status);
            console.log('Data:', JSON.stringify(err.response.data).substring(0, 500));
        }
        process.exit(1);
    }
}

test();
