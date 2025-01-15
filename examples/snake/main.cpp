#include <iostream>
#include <ctime>
#include <string>
#include <vector>
#include <algorithm>
#include <Windows.h>
#include <conio.h>

constexpr int ARENA_HEIGHT = 20;
constexpr int ARENA_WIDTH = ARENA_HEIGHT * 2;

enum class Direction {
    None, Up, Down, Left, Right
};

struct GameState {
    std::vector<std::pair<int, int>> snake_body_parts;
    int food_x, food_y;
    bool finished;
    Direction snake_direction;
};

int get_random_arena_x() {
    return rand() % (ARENA_WIDTH - 2) + 1;
}

int get_random_arena_y() {
    return rand() % (ARENA_HEIGHT - 2) + 1;
}

GameState init_game() {
    GameState game_state;
    srand(time(nullptr));

    int snake_x = get_random_arena_x();
    int snake_y = get_random_arena_y();
    game_state.snake_body_parts.emplace_back(snake_x, snake_y);

    game_state.food_x = get_random_arena_x();
    game_state.food_y = get_random_arena_y();

    game_state.finished = false;
    game_state.snake_direction = Direction::Up;

    return game_state;
}

void draw(const GameState& game_state) {
    for (int j = 0; j < ARENA_HEIGHT; ++j) {
        for (int i = 0; i < ARENA_WIDTH; ++i) {
            const auto& snake = game_state.snake_body_parts;
            if (std::find(snake.begin(), snake.end(), std::make_pair(i,j)) != snake.end()) {
                std::cout << "@";
            } else if (i == game_state.food_x && j == game_state.food_y) {
                std::cout << "a";
            } else {
                std::cout << ((i == 0 || j == 0 || i == ARENA_WIDTH - 1 || j == ARENA_HEIGHT - 1) ? "*" : " ");
            }
        }
        std::cout << "\n";
    }
}

void handle_input(GameState& game_state) {
    if (_kbhit()) {
        switch (_getch()) {
            case 'w':
            if (game_state.snake_direction != Direction::Down) {
                game_state.snake_direction = Direction::Up;
            }
            break;
            case 'a':
            if (game_state.snake_direction != Direction::Right) {
                game_state.snake_direction = Direction::Left;
            }
            break;
            case 's':
            if (game_state.snake_direction != Direction::Up) {
                game_state.snake_direction = Direction::Down;
            }
            break;
            case 'd':
            if (game_state.snake_direction != Direction::Left) {
                game_state.snake_direction = Direction::Right;
            }
            break;
            default: break;
        }
    }
}

void update(GameState& game_state) {
    auto& snake_body_parts = game_state.snake_body_parts;

    auto [head_x, head_y] = snake_body_parts[0];
    int new_head_x = head_x, new_head_y = head_y;
    switch (game_state.snake_direction) {
        case Direction::Up: new_head_y--; break;
        case Direction::Down: new_head_y++; break;
        case Direction::Left: new_head_x--; break;
        case Direction::Right: new_head_x++; break;
        default: break;
    }

    if (new_head_x >= ARENA_WIDTH - 1) {
        new_head_x = 1;
    } else if (new_head_x <= 0) {
        new_head_x = ARENA_WIDTH - 2;
    }
    if (new_head_y >= ARENA_HEIGHT - 1) {
        new_head_y = 1;
    } else if (new_head_y <= 0) {
        new_head_y = ARENA_HEIGHT - 2;
    }

    auto last_part = snake_body_parts.back();
    snake_body_parts.pop_back();

    if (std::find(snake_body_parts.begin(), snake_body_parts.end(), std::make_pair(new_head_x, new_head_y)) != snake_body_parts.end()) {
        game_state.finished = true;
    } else if (new_head_x == game_state.food_x && new_head_y == game_state.food_y) {
        snake_body_parts.push_back(last_part);
        game_state.food_x = get_random_arena_x();
        game_state.food_y = get_random_arena_y();
    }
    snake_body_parts.insert(snake_body_parts.begin(), std::make_pair(new_head_x, new_head_y));
}

int main() {
    GameState game_state = init_game();

    while (!game_state.finished) {
        system("cls");
        draw(game_state);
        handle_input(game_state);
        update(game_state);
        Sleep(0x32);
    }
}