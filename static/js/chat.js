let socket = io("/groupchat");
let currentPrivateTarget = null;

socket.on('connect', () => {
    socket.emit('join_room', {
        room: `post_${postId}`,
        post_id: postId,
        username: currentUsername
    });
});


// -------------------- 그룹 채팅 --------------------


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
    messageElement.innerHTML = `<b>${data.username}:</b> ${linkify(data.msg)}`;
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
    box.innerHTML += `<div><strong>${from}</strong>: ${linkify(message)}</div>`;
    box.scrollTop = box.scrollHeight;
});

socket.on("load_private_chat", ({ messages }) => {
    const box = document.getElementById("privateChatBox");
    box.innerHTML = '';
    messages.forEach(msg => {
        box.innerHTML += `<div><strong>${msg.from}</strong>: ${linkify(msg.message)}</div>`;
    });
    box.scrollTop = box.scrollHeight;
});
//기타----------------------------------------------------------------
function linkify(text) {
    const urlPattern = /(https?:\/\/[^\s]+)/g;
    return text.replace(urlPattern, url => {
        return `<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`;
    });
}
socket.on('update_active_users', function(usernames) {
    const userList = document.getElementById('activeUsers');
    userList.innerHTML = '';
    
    usernames.forEach(username => {
        const li = document.createElement('li');
        li.innerHTML = `<span class="online-dot"></span> ${username}`;
        userList.appendChild(li);
    });
});

document.addEventListener('DOMContentLoaded', () => {
    const groupInput = document.getElementById('groupMsg');
    const privateInput = document.getElementById('privateMsg');

    if (groupInput) {
        groupInput.addEventListener('keydown', function (event) {
            if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault();
                sendGroupMessage();
            }
        });
    }

    if (privateInput) {
        privateInput.addEventListener('keydown', function (event) {
            if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault();
                sendPrivateMessage();
            }
        });
    }
});