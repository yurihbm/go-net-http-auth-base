package domain

type Page[T any] struct {
	Items      []T
	NextCursor *string
	Total      int64
}

func NewPage[T any](items []T, total int64, limit int, cursorOf func(T) string) *Page[T] {
	page := &Page[T]{Items: items, Total: total}
	if len(items) > limit {
		page.Items = items[:limit]
		next := cursorOf(page.Items[limit-1])
		page.NextCursor = &next
	}
	return page
}
