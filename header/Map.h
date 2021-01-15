#ifndef __MAP__
#define __MAP__


template<typename Key_t, typename Data_t>
class CMap
{
public:
    CMap(void);
    ~CMap(void);

    void push(Key_t& key, Data_t& data);
    uint32_t get_length(void) { return m_length; }
    Key_t get_key(uint32_t index);
    Data_t get_value(uint32_t index);

private:
    template<typename Node_Key_t, typename Node_Data_t>
    class CMapNode
    {
        friend class CMap<Node_Key_t, Node_Data_t>;
    public:
        CMapNode(void)
        {}

    private:
        Node_Key_t m_key;
        Node_Data_t m_data;
        CMapNode<Node_Key_t, Node_Data_t>* prev;
        CMapNode<Node_Key_t, Node_Data_t>* next;
    };

    uint32_t m_length;
    CMapNode<Key_t, Data_t>* m_node;
};


template<typename Key_t, typename Data_t>
CMap<Key_t, Data_t>::CMap(void)
    : m_length(0)
{
    // Circular doubly linked list
    // Make dummy node
    m_node = new CMapNode<Key_t, Data_t>;
    m_node->prev = m_node;
    m_node->next = m_node;
}

template<typename Key_t, typename Data_t>
CMap<Key_t, Data_t>::~CMap(void)
{
    CMapNode<Key_t, Data_t>* temp = m_node->next;
    for (uint32_t i = 0; i < m_length; i++) {
        temp = temp->next;
        delete temp->prev;
    }

    delete m_node;
}

template<typename Key_t, typename Data_t>
void CMap<Key_t, Data_t>::push(Key_t& key, Data_t& data)
{
    CMapNode<Key_t, Data_t>* cur = m_node->next;
    for (int i = 0; i < m_length; i++) {
        if (cur->m_key == key)
            break;
        cur = cur->next;
    }

    if (cur == m_node) {
        // if key does not exist, make new node
        CMapNode<Key_t, Data_t>* new_node = new CMapNode<Key_t, Data_t>();
        new_node->m_key = key;
        new_node->m_data = data;

        new_node->prev = m_node->prev;
        new_node->next = m_node;

        m_node->prev->next = new_node;
        m_node->prev = new_node;

        m_length++;
    }
    else {
        // if key exists, add to it.
        cur->m_data += data;
    }
}
template<typename Key_t, typename Data_t>
Key_t CMap<Key_t, Data_t>::get_key(uint32_t index)
{
    if (m_length <= index) {
        cerr << "get_key out of range" << endl;
        exit(1);
    }

    CMapNode<Key_t, Data_t>* temp = m_node->next;
    for (uint32_t i = 0; i < index; i++) {
        temp = temp->next;
    }

    return Key_t(temp->m_key);
}

template<typename Key_t, typename Data_t>
Data_t CMap<Key_t, Data_t>::get_value(uint32_t index)
{
    if (m_length <= index) {
        cerr << "get_key out of range" << endl;
        exit(1);
    }

    CMapNode<Key_t, Data_t>* temp = m_node->next;
    for (uint32_t i = 0; i < index; i++) {
        temp = temp->next;
    }

    return Data_t(temp->m_data);
}

#endif