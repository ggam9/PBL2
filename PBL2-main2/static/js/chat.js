let socket = io();
let currentPrivateTarget = null;

// -------------------- 그룹 채팅 --------------------
socket.on('connect', () => {
    socket.emit('join_room', { room: `post_${postId}` });
});

function sendGroupMessage() {
    const input = document.getElementById('groupMsg');
    const msg = input.value.trim();
    if (!msg) return;

    socket.emit('group_message', {
        room: `post_${postId}`,
    msg: msg,
    
    });

    input.value = '';
}

socket.on('group_message', data => {
    const chatBox = document.getElementById('groupChatBox');
    const messageElement = document.createElement('div');
    messageElement.innerHTML = `<b>${data.username}:</b> ${data.msg}`;
    chatBox.appendChild(messageElement);
    chatBox.scrollTop = chatBox.scrollHeight;
});


// -------------------- 1:1 채팅 --------------------
// 사용자 클릭 시 1:1 채팅 열기
function openPrivateChat(targetUsername) {
    currentPrivateTarget = targetUsername;
    document.getElementById("private-chat-title").innerText = `1:1 채팅 - ${targetUsername}`;
    document.getElementById("privateChatBox").innerHTML = '';
    document.getElementById("private-chat-panel").style.display = 'block';
    
    socket.emit("load_private_chat", {
        from: currentUsername,
        to: targetUsername
    });
}

// 닫기 버튼
function closePrivateChat() {
    currentPrivateTarget = null;
    document.getElementById("private-chat-panel").style.display = 'none';
}

// 메시지 보내기
function sendPrivateMessage() {
    const message = document.getElementById("privateMsg").value;
    if (!currentPrivateTarget || !message) return;

    socket.emit("private_message", {
        from: currentUsername,
        to: currentPrivateTarget,
        message: message
    });
    document.getElementById("privateMsg").value = '';
}

// 수신
socket.on("private_message", ({ from, message }) => {
    const box = document.getElementById("privateChatBox");
    box.innerHTML += `<div><strong>${from}</strong>: ${message}</div>`;
    box.scrollTop = box.scrollHeight;
});

socket.on("load_private_chat", ({ messages }) => {
    const box = document.getElementById("privateChatBox");
    box.innerHTML = '';
    messages.forEach(msg => {
        box.innerHTML += `<div><strong>${msg.from}</strong>: ${msg.message}</div>`;
    });
    box.scrollTop = box.scrollHeight;
});
